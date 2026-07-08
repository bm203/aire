"""Deep memory control tests: deletion verification, retention, PII, isolation.

Uses a real LangGraph SqliteSaver database as the inspected artifact and a
fake PII scanner (the scanner is a protocol; Presidio-specific behavior is
covered in test_detectors_pii.py).
"""

import hashlib
import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

pytest.importorskip("langgraph.checkpoint.sqlite")
from langgraph.checkpoint.sqlite import SqliteSaver  # noqa: E402

from aire.core.events import EventType  # noqa: E402
from aire.detectors import DetectorRunner  # noqa: E402
from aire.detectors.memory_retention import MemoryRetentionControl  # noqa: E402
from aire.detectors.pii import PIIMatch  # noqa: E402
from aire.store import EvidenceStore  # noqa: E402

NOW = datetime(2026, 7, 8, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def store(tmp_path):
    s = EvidenceStore(tmp_path / "evidence.db")
    yield s
    s.close()


@pytest.fixture
def memory_db(tmp_path):
    return tmp_path / "memory.db"


def write_checkpoint(memory_db, thread_id, *, cid="ckpt-1", ts=None, values=None):
    conn = sqlite3.connect(memory_db)
    saver = SqliteSaver(conn)
    saver.put(
        {"configurable": {"thread_id": thread_id, "checkpoint_ns": ""}},
        {
            "v": 1,
            "id": cid,
            "ts": (ts or NOW).isoformat(),
            "channel_values": values or {"messages": [{"role": "user", "content": "hello"}]},
            "channel_versions": {"messages": 1},
            "versions_seen": {},
            "pending_sends": [],
        },
        {"source": "update", "step": 1},
        {},
    )
    conn.commit()
    conn.close()


def delete_thread_rows(memory_db, thread_id):
    conn = sqlite3.connect(memory_db)
    for table in ("checkpoints", "writes"):
        conn.execute(f"DELETE FROM {table} WHERE thread_id=?", (thread_id,))  # noqa: S608
    conn.commit()
    conn.close()


def record_delete(store, thread_id):
    return store.append(
        session_id=thread_id,
        app="t",
        event_type=EventType.MEMORY_DELETE,
        payload={"memory.system": "langgraph.checkpointer", "thread_id": thread_id},
    )


def record_write(store, thread_id):
    return store.append(
        session_id=thread_id,
        app="t",
        event_type=EventType.MEMORY_WRITE,
        payload={"memory.system": "langgraph.checkpointer", "thread_id": thread_id},
    )


def control(memory_db, **kwargs):
    kwargs.setdefault("now", NOW)
    return MemoryRetentionControl(memory_db, **kwargs)


def run(store, det):
    return DetectorRunner([det]).run(store)


class FakeScanner:
    """PIIScanner protocol double — flags the literal 'alice@example.com'."""

    def scan(self, text):
        needle = "alice@example.com"
        idx = text.find(needle)
        if idx < 0:
            return []
        return [PIIMatch(entity_type="EMAIL_ADDRESS", score=1.0, start=idx, end=idx + len(needle))]


class TestDeletionVerification:
    def test_honored_deletion_is_quiet(self, store, memory_db):
        write_checkpoint(memory_db, "user-1")
        delete_thread_rows(memory_db, "user-1")  # app really deleted
        record_delete(store, "user-1")
        outcome = run(store, control(memory_db))
        assert outcome.recorded == []

    def test_unhonored_deletion_is_critical(self, store, memory_db):
        write_checkpoint(memory_db, "user-1")  # data still there...
        deletion = record_delete(store, "user-1")  # ...but deletion was claimed
        outcome = run(store, control(memory_db))
        [rec] = outcome.recorded
        assert rec.payload["severity"] == "critical"
        assert "deletion NOT honored" in rec.payload["summary"]
        assert rec.payload["detail"]["surviving_rows"]["checkpoints"] == 1
        assert rec.payload["source_event_ids"] == [deletion.event_id]
        assert rec.payload["source_event_hashes"] == [deletion.hash]

    def test_rewrite_after_delete_is_legitimate(self, store, memory_db):
        write_checkpoint(memory_db, "user-1")
        record_delete(store, "user-1")
        record_write(store, "user-1")  # app re-created memory afterwards
        outcome = run(store, control(memory_db))
        assert outcome.recorded == []

    def test_missing_memory_db_reports_control_gap(self, store, tmp_path):
        record_delete(store, "user-1")
        outcome = run(store, control(tmp_path / "nope.db"))
        [rec] = outcome.recorded
        assert "control did not run" in rec.payload["summary"]


class TestRetention:
    def test_old_checkpoint_exceeds_retention(self, store, memory_db):
        write_checkpoint(memory_db, "user-1", ts=NOW - timedelta(days=100))
        outcome = run(store, control(memory_db, retention_max_days=30))
        [rec] = outcome.recorded
        assert rec.payload["severity"] == "high"
        assert "retention exceeded" in rec.payload["summary"]
        assert rec.payload["detail"]["age_days"] == 100

    def test_fresh_checkpoint_is_quiet(self, store, memory_db):
        write_checkpoint(memory_db, "user-1", ts=NOW - timedelta(days=3))
        outcome = run(store, control(memory_db, retention_max_days=30))
        assert outcome.recorded == []

    def test_no_retention_configured_skips_check(self, store, memory_db):
        write_checkpoint(memory_db, "user-1", ts=NOW - timedelta(days=1000))
        outcome = run(store, control(memory_db))
        assert outcome.recorded == []


class TestPIIInMemory:
    def test_pii_in_latest_checkpoint(self, store, memory_db):
        write_checkpoint(
            memory_db,
            "user-1",
            values={"messages": [{"role": "user", "content": "mail me at alice@example.com"}]},
        )
        outcome = run(store, control(memory_db, pii_scanner=FakeScanner()))
        [rec] = outcome.recorded
        assert rec.payload["severity"] == "high"
        assert rec.payload["detail"]["entity_counts"] == {"EMAIL_ADDRESS": 1}
        # security: the finding never copies the PII value itself
        assert "alice@example.com" not in str(rec.payload)

    def test_clean_memory_is_quiet(self, store, memory_db):
        write_checkpoint(memory_db, "user-1")
        outcome = run(store, control(memory_db, pii_scanner=FakeScanner()))
        assert outcome.recorded == []


class TestCrossSessionReads:
    def test_foreign_read_is_flagged(self, store, memory_db):
        write_checkpoint(memory_db, "user-1")
        store.append(
            session_id="user-2",  # a different session...
            app="t",
            event_type=EventType.MEMORY_READ,
            payload={"thread_id": "user-1", "op": "get"},  # ...reads user-1's memory
        )
        outcome = run(store, control(memory_db))
        [rec] = outcome.recorded
        assert "cross-session memory access" in rec.payload["summary"]
        assert rec.payload["detail"]["reader_session"] == "user-2"

    def test_own_thread_read_is_quiet(self, store, memory_db):
        write_checkpoint(memory_db, "user-1")
        store.append(
            session_id="user-1",
            app="t",
            event_type=EventType.MEMORY_READ,
            payload={"thread_id": "user-1", "op": "get"},
        )
        outcome = run(store, control(memory_db))
        assert outcome.recorded == []


class TestReadOnlyGuarantee:
    def test_control_never_modifies_the_host_db(self, store, memory_db):
        write_checkpoint(memory_db, "user-1", ts=NOW - timedelta(days=100))
        record_delete(store, "user-1")
        digest_before = hashlib.sha256(memory_db.read_bytes()).hexdigest()
        run(store, control(memory_db, retention_max_days=30, pii_scanner=FakeScanner()))
        digest_after = hashlib.sha256(memory_db.read_bytes()).hexdigest()
        assert digest_before == digest_after
