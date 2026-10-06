"""Background evidence writer: the host thread never waits on the database."""

import os
import subprocess
import sys
import textwrap
import time

import pytest

from aire.collectors import _writer
from aire.collectors.base import Sensor
from aire.core.events import EventType
from aire.store import EvidenceStore

fcntl = pytest.importorskip("fcntl")


@pytest.fixture
def store(tmp_path):
    s = EvidenceStore(tmp_path / "evidence.db")
    yield s
    s.close()


def record(sensor, i, payload=None):
    sensor.record(EventType.TOOL_CALL, lambda: payload or {"gen_ai.tool.name": "t", "i": i})


class HeldLock:
    """Hold the writer's cross-process lock, as a slow writer in another worker would."""

    def __init__(self, store):
        self.fd = os.open(str(store.path) + ".lock", os.O_RDWR | os.O_CREAT, 0o600)

    def __enter__(self):
        fcntl.flock(self.fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        fcntl.flock(self.fd, fcntl.LOCK_UN)
        os.close(self.fd)


def test_host_never_waits_while_the_writer_is_blocked(store):
    sensor = Sensor(store=store, app="a")
    with HeldLock(store):
        started = time.perf_counter()
        for i in range(50):
            record(sensor, i)
        elapsed = time.perf_counter() - started
        assert elapsed < 0.5  # 50 records while every write is blocked
        assert sensor.dropped == 0
    assert sensor.flush(5)
    assert len(list(store.events())) == 50


def test_stored_time_is_when_the_event_happened(store):
    from datetime import UTC, datetime

    sensor = Sensor(store=store, app="a")
    with HeldLock(store):
        called_at = datetime.now(UTC)
        record(sensor, 0)
        time.sleep(0.5)  # the write cannot happen before the lock is released
        released_at = datetime.now(UTC)
    sensor.flush(5)
    (event,) = list(store.events())
    stored = datetime.fromisoformat(event.ts)
    assert abs((stored - called_at).total_seconds()) < 0.1
    assert stored < released_at


def test_full_queue_is_a_counted_drop_that_becomes_evidence(store):
    sensor = Sensor(store=store, app="a", max_queue=5)
    with HeldLock(store):
        # The writer may already hold one item; the queue takes 5 more.
        for i in range(20):
            record(sensor, i)
        assert sensor.dropped >= 14
        dropped = sensor.dropped
    sensor.flush(5)
    record(sensor, 99)  # next successful hand-off carries the drop notice
    sensor.flush(5)
    notices = [e for e in store.events() if e.event_type is EventType.SENSOR_DROPPED]
    assert sum(e.payload["count"] for e in notices) == dropped
    assert store.verify().ok


def test_writer_side_failure_is_recorded_as_a_drop(store, monkeypatch):
    sensor = Sensor(store=store, app="a")
    real_append = EvidenceStore.append
    calls = {"n": 0}

    def flaky_append(self, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("disk full")
        return real_append(self, **kw)

    monkeypatch.setattr(EvidenceStore, "append", flaky_append)
    record(sensor, 0)  # fails inside the writer
    sensor.flush(5)
    record(sensor, 1)
    sensor.flush(5)
    monkeypatch.setattr(EvidenceStore, "append", real_append)
    types = [e.event_type for e in store.events()]
    assert types == [EventType.SENSOR_DROPPED, EventType.TOOL_CALL]


def test_evidence_is_captured_at_call_time(store):
    sensor = Sensor(store=store, app="a")
    messages = [{"role": "user", "content": "original"}]
    with HeldLock(store):
        sensor.record(EventType.LLM_REQUEST, lambda: {"messages": [dict(m) for m in messages]})
        messages[0]["content"] = "changed by the host after the call"
    sensor.flush(5)
    (event,) = list(store.events())
    assert event.payload["messages"][0]["content"] == "original"


def test_a_process_reads_its_own_writes_without_flushing(store):
    sensor = Sensor(store=store, app="a")
    for i in range(10):
        record(sensor, i)
    assert len(list(store.events())) == 10  # events() waits for pending writes
    assert store.verify().checked == 10


def test_lock_file_is_owner_only(store):
    sensor = Sensor(store=store, app="a")
    record(sensor, 0)
    sensor.flush(5)
    mode = os.stat(str(store.path) + ".lock").st_mode & 0o777
    assert mode == 0o600


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs fork")
@pytest.mark.filterwarnings("ignore::DeprecationWarning")  # fork with threads: the case under test
def test_forked_worker_gets_its_own_writer(store):
    sensor = Sensor(store=store, app="parent")
    record(sensor, 0)
    sensor.flush(5)
    pid = os.fork()
    if pid == 0:  # child: inherited writer thread does not exist here
        try:
            child_store = EvidenceStore(store.path)
            child = Sensor(store=child_store, app="child")
            for i in range(5):
                record(child, i)
            ok = child.flush(5)
        finally:
            os._exit(0 if ok else 1)
    _, status = os.waitpid(pid, 0)
    assert os.WEXITSTATUS(status) == 0
    record(sensor, 1)
    events = list(store.events())
    assert [e.app for e in events].count("child") == 5
    assert len(events) == 7 and store.verify().ok


def test_normal_shutdown_flushes_the_queue(tmp_path):
    db = tmp_path / "evidence.db"
    script = textwrap.dedent(f"""
        from aire.collectors.base import Sensor
        from aire.core.events import EventType
        from aire.store import EvidenceStore
        s = Sensor(store=EvidenceStore({str(db)!r}), app="a")
        for i in range(200):
            s.record(EventType.TOOL_CALL, lambda i=i: {{"i": i}})
        # exit without flushing: the atexit hook must write everything queued
    """)
    subprocess.run([sys.executable, "-c", script], check=True, timeout=60)
    assert len(list(EvidenceStore(db, read_only=True).events())) == 200


def test_synchronous_mode_still_available(store):
    sensor = Sensor(store=store, app="a", background=False)
    assert sensor._writer is None
    record(sensor, 0)
    assert _writer.flush(store.path)  # nothing pending
    assert len(list(store.events())) == 1


def test_drops_at_the_end_of_a_run_still_become_evidence(store):
    sensor = Sensor(store=store, app="a", max_queue=3)
    with HeldLock(store):
        for i in range(30):
            record(sensor, i)
        dropped = sensor.dropped
        assert dropped > 0
    assert sensor.flush(5)  # no later event carries the notice; flush must
    notices = [e for e in store.events() if e.event_type is EventType.SENSOR_DROPPED]
    written = [e for e in store.events() if e.event_type is EventType.TOOL_CALL]
    assert sum(e.payload["count"] for e in notices) == dropped
    assert len(written) + dropped == 30 and sensor.dropped == 0


def test_shutdown_reports_pending_drops(tmp_path):
    db = tmp_path / "evidence.db"
    script = textwrap.dedent(f"""
        import fcntl, os
        from aire.collectors.base import Sensor
        from aire.core.events import EventType
        from aire.store import EvidenceStore
        store = EvidenceStore({str(db)!r})
        s = Sensor(store=store, app="a", max_queue=2)
        fd = os.open({str(db)!r} + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        for i in range(20):
            s.record(EventType.TOOL_CALL, lambda i=i: {{"i": i}})
        fcntl.flock(fd, fcntl.LOCK_UN)
        print(s.dropped)
        # exit without flushing: shutdown must report the drops as evidence
    """)
    out = subprocess.run([sys.executable, "-c", script], check=True, timeout=60,
                         capture_output=True, text=True)
    dropped = int(out.stdout.strip())
    events = list(EvidenceStore(db, read_only=True).events())
    notices = [e for e in events if e.event_type is EventType.SENSOR_DROPPED]
    assert dropped > 0 and sum(e.payload["count"] for e in notices) == dropped
