"""LangGraph checkpointer collector tests (skipped without the extra)."""

import pytest

langgraph_base = pytest.importorskip("langgraph.checkpoint.base")
from langgraph.checkpoint.memory import MemorySaver  # noqa: E402

from aire.collectors.langgraph import InstrumentedSaver  # noqa: E402
from aire.core.events import EventType  # noqa: E402
from aire.store import EvidenceStore  # noqa: E402


@pytest.fixture
def store(tmp_path):
    s = EvidenceStore(tmp_path / "evidence.db")
    yield s
    s.close()


@pytest.fixture
def saver(store):
    return InstrumentedSaver(MemorySaver(), store=store, app="t")


def make_checkpoint(cid: str, values: dict) -> dict:
    return {
        "v": 1,
        "id": cid,
        "ts": "2026-07-08T12:00:00+00:00",
        "channel_values": values,
        "channel_versions": {},
        "versions_seen": {},
        "pending_sends": [],
    }


CONFIG = {"configurable": {"thread_id": "thread-1", "checkpoint_ns": ""}}


def events(store, event_type):
    return list(store.events(event_type=event_type))


class TestPut:
    def test_put_records_memory_write_with_content(self, store, saver):
        saver.put(
            CONFIG,
            make_checkpoint("ckpt-1", {"messages": [{"role": "user", "content": "my SSN is X"}]}),
            {"source": "update", "step": 1},
            {},
        )
        writes = events(store, EventType.MEMORY_WRITE)
        assert len(writes) == 1
        w = writes[0]
        assert w.session_id == "thread-1"
        assert w.payload["thread_id"] == "thread-1"
        assert w.payload["checkpoint_id"] == "ckpt-1"
        # content is recorded — the PII detector and memory control need it
        assert "my SSN is X" in str(w.payload["channel_values"])

    def test_put_delegates_to_inner_saver(self, store, saver):
        saver.put(CONFIG, make_checkpoint("ckpt-1", {"k": "v"}), {"step": 1}, {})
        found = saver.get_tuple(CONFIG)
        assert found is not None
        assert found.checkpoint["id"] == "ckpt-1"


class TestGet:
    def test_get_records_memory_read(self, store, saver):
        saver.put(CONFIG, make_checkpoint("ckpt-1", {"k": "v"}), {"step": 1}, {})
        saver.get_tuple(CONFIG)
        reads = events(store, EventType.MEMORY_READ)
        assert len(reads) == 1
        assert reads[0].payload["op"] == "get"
        assert reads[0].payload["found"] is True
        assert reads[0].payload["checkpoint_id"] == "ckpt-1"

    def test_miss_recorded_as_not_found(self, store, saver):
        saver.get_tuple({"configurable": {"thread_id": "nope", "checkpoint_ns": ""}})
        reads = events(store, EventType.MEMORY_READ)
        assert reads[0].payload["found"] is False
        assert reads[0].session_id == "nope"


class TestDelete:
    def test_delete_thread_records_memory_delete(self, store, saver):
        if not hasattr(saver._inner, "delete_thread"):
            pytest.skip("installed langgraph-checkpoint lacks delete_thread")
        saver.put(CONFIG, make_checkpoint("ckpt-1", {"k": "v"}), {"step": 1}, {})
        saver.delete_thread("thread-1")
        deletes = events(store, EventType.MEMORY_DELETE)
        assert len(deletes) == 1
        assert deletes[0].payload["thread_id"] == "thread-1"
        assert saver.get_tuple(CONFIG) is None


class TestFailOpen:
    def test_store_failure_does_not_break_memory_ops(self, saver, store):
        def broken_append(**kwargs):
            raise RuntimeError("disk on fire")

        store.append = broken_append
        saver.put(CONFIG, make_checkpoint("ckpt-1", {"k": "v"}), {"step": 1}, {})  # no raise
        assert saver.get_tuple(CONFIG) is not None  # inner saver unaffected
        assert saver._sensor.dropped >= 2
