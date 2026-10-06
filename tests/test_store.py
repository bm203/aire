import json
import sqlite3

import pytest

from aire.core.events import GENESIS_HASH, EventType
from aire.store import EvidenceStore


@pytest.fixture
def store(tmp_path):
    s = EvidenceStore(tmp_path / "evidence.db")
    yield s
    s.close()


def fill(store: EvidenceStore, n: int = 5) -> list:
    return [
        store.append(
            session_id=f"sess-{i % 2}",
            app="test-app",
            event_type=EventType.LLM_REQUEST if i % 2 == 0 else EventType.MEMORY_WRITE,
            payload={"i": i},
        )
        for i in range(n)
    ]


def raw_conn(store: EvidenceStore) -> sqlite3.Connection:
    """Attacker's-eye connection: direct file access, triggers droppable."""
    return sqlite3.connect(store.path)


def rewrite_chain(store: EvidenceStore, mutate=None, drop_seqs=()) -> None:
    """Forge history the way someone with write access could: drop the
    append-only triggers, change or remove events, then recompute every later
    hash so the chain is internally consistent again. The chain has no secret,
    so nothing stops this; only an anchor recorded elsewhere can reveal it."""
    events = list(store.events())
    with raw_conn(store) as conn:
        for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'"):
            conn.execute(f"DROP TRIGGER {name}")
        rows = dict(conn.execute("SELECT event_id, seq FROM events"))
        for seq in drop_seqs:
            conn.execute("DELETE FROM events WHERE seq = ?", (seq,))
        prev = GENESIS_HASH
        for event in events:
            if rows[event.event_id] in drop_seqs:
                continue
            payload = mutate(dict(event.payload)) if mutate else event.payload
            forged = event.model_copy(update={"payload": payload, "prev_hash": prev})
            new_hash = forged.compute_hash()
            conn.execute(
                "UPDATE events SET payload = ?, prev_hash = ?, hash = ? WHERE event_id = ?",
                (json.dumps(payload, sort_keys=True), prev, new_hash, event.event_id),
            )
            prev = new_hash
        conn.commit()


class TestAppend:
    def test_chain_links(self, store):
        events = fill(store)
        assert events[0].prev_hash == GENESIS_HASH
        for prev, cur in zip(events, events[1:], strict=False):
            assert cur.prev_hash == prev.hash

    def test_head_hash_tracks_last_event(self, store):
        assert store.head_hash() == GENESIS_HASH
        events = fill(store)
        assert store.head_hash() == events[-1].hash

    def test_round_trip(self, store):
        written = fill(store)
        read = list(store.events())
        assert read == written

    def test_filters(self, store):
        fill(store, 6)
        assert all(e.session_id == "sess-0" for e in store.events(session_id="sess-0"))
        assert len(list(store.events(session_id="sess-0"))) == 3
        assert len(list(store.events(event_type=EventType.MEMORY_WRITE))) == 3
        assert (
            len(list(store.events(session_id="sess-1", event_type=EventType.MEMORY_WRITE))) == 3
        )


class TestAppendOnly:
    def test_update_is_rejected(self, store):
        fill(store, 1)
        with raw_conn(store) as conn, pytest.raises(sqlite3.DatabaseError, match="append-only"):
            conn.execute("UPDATE events SET app = 'evil'")

    def test_delete_is_rejected(self, store):
        fill(store, 1)
        with raw_conn(store) as conn, pytest.raises(sqlite3.DatabaseError, match="append-only"):
            conn.execute("DELETE FROM events")


class TestVerify:
    def test_intact_chain_verifies(self, store):
        fill(store, 10)
        result = store.verify()
        assert result.ok
        assert result.checked == 10

    def test_empty_store_verifies(self, store):
        assert store.verify().ok

    @pytest.mark.parametrize(
        ("column", "value"),
        [
            ("ts", "'1999-01-01T00:00:00+00:00'"),
            ("session_id", "'forged'"),
            ("app", "'forged'"),
            ("event_type", "'memory.delete'"),
            ("payload", """'{"i": 999}'"""),
            ("prev_hash", f"'{'f' * 64}'"),
            ("hash", f"'{'f' * 64}'"),
        ],
    )
    def test_tampering_any_column_is_detected_and_localized(self, store, column, value):
        events = fill(store, 5)
        target_seq = 3  # tamper the middle event
        with raw_conn(store) as conn:
            conn.execute("DROP TRIGGER events_no_update")
            conn.execute(f"UPDATE events SET {column} = {value} WHERE seq = ?", (target_seq,))
            conn.commit()
        result = store.verify()
        assert not result.ok
        assert result.first_bad_seq is not None
        # Detection localizes to the tampered event or its successor (a forged
        # `hash` column surfaces as a chain break on the next event).
        assert result.first_bad_seq in (target_seq, target_seq + 1)
        assert result.checked < len(events)

    def test_deleting_a_middle_event_breaks_the_chain(self, store):
        fill(store, 5)
        with raw_conn(store) as conn:
            conn.execute("DROP TRIGGER events_no_delete")
            conn.execute("DELETE FROM events WHERE seq = 3")
            conn.commit()
        result = store.verify()
        assert not result.ok
        assert "chain break" in result.reason

    def test_payload_semantic_tamper_is_detected(self, store):
        """Even a re-serialized, key-sorted payload edit breaks the hash."""
        fill(store, 3)
        with raw_conn(store) as conn:
            conn.execute("DROP TRIGGER events_no_update")
            payload = json.loads(
                conn.execute("SELECT payload FROM events WHERE seq = 2").fetchone()[0]
            )
            payload["i"] = 12345
            conn.execute(
                "UPDATE events SET payload = ? WHERE seq = 2",
                (json.dumps(payload, sort_keys=True),),
            )
            conn.commit()
        assert not store.verify().ok


class TestAnchoring:
    """The chain alone proves internal consistency; an anchor proves history."""

    def test_verify_reports_head(self, store):
        assert store.verify().head is None  # empty store
        events = fill(store, 3)
        result = store.verify()
        assert result.head == f"3:{events[-1].hash}"
        assert not result.anchor_checked

    def test_rewritten_chain_passes_alone_but_fails_against_anchor(self, store):
        fill(store, 5)
        recorded = store.verify().head
        rewrite_chain(store, mutate=lambda p: {**p, "i": 999} if p["i"] == 2 else p)
        # The documented limitation: a full rewrite is internally consistent.
        assert store.verify().ok
        result = store.verify(expect_head=recorded)
        assert not result.ok
        assert result.reason.startswith("anchor mismatch")
        assert result.first_bad_seq == 5

    def test_removed_event_with_recomputed_chain_fails_against_anchor(self, store):
        fill(store, 5)
        recorded = store.verify().head
        rewrite_chain(store, drop_seqs=(2,))
        assert store.verify().ok
        assert not store.verify(expect_head=recorded).ok

    def test_truncation_through_the_anchor_is_detected(self, store):
        fill(store, 5)
        recorded = store.verify().head
        rewrite_chain(store, drop_seqs=(4, 5))
        result = store.verify(expect_head=recorded)
        assert not result.ok
        assert result.reason.startswith("anchor not found")

    def test_events_appended_after_the_anchor_still_verify(self, store):
        fill(store, 3)
        recorded = store.verify().head
        fill(store, 2)
        result = store.verify(expect_head=recorded)
        assert result.ok and result.anchor_checked
        assert result.head.startswith("5:")

    @pytest.mark.parametrize("bad", ["", "abc", "5", "x:" + "a" * 64, "5:" + "a" * 63])
    def test_malformed_anchor_is_rejected(self, store, bad):
        fill(store, 1)
        with pytest.raises(ValueError, match="anchor must look like"):
            store.verify(expect_head=bad)


class TestCli:
    def test_verify_command(self, store, tmp_path):
        from typer.testing import CliRunner

        from aire.cli import app

        fill(store, 3)
        runner = CliRunner()
        ok = runner.invoke(app, ["verify", str(store.path)])
        assert ok.exit_code == 0
        assert "chain intact" in ok.output

        with raw_conn(store) as conn:
            conn.execute("DROP TRIGGER events_no_update")
            conn.execute("UPDATE events SET app = 'evil' WHERE seq = 1")
            conn.commit()
        bad = runner.invoke(app, ["verify", str(store.path)])
        assert bad.exit_code == 1

        missing = runner.invoke(app, ["verify", str(tmp_path / "nope.db")])
        assert missing.exit_code == 2


    def test_verify_prints_head_and_checks_anchor(self, store):
        from typer.testing import CliRunner

        from aire.cli import app

        fill(store, 3)
        runner = CliRunner()
        first = runner.invoke(app, ["verify", str(store.path)])
        lines = first.output.splitlines()
        head = next(line.split("head: ")[1] for line in lines if line.startswith("head: "))
        assert "internal consistency only" in first.output

        anchored = runner.invoke(app, ["verify", str(store.path), "--expect-head", head])
        assert anchored.exit_code == 0 and f"anchor {head} matches" in anchored.output

        rewrite_chain(store, mutate=lambda p: {**p, "i": -1})
        assert runner.invoke(app, ["verify", str(store.path)]).exit_code == 0
        forged = runner.invoke(app, ["verify", str(store.path), "--expect-head", head])
        assert forged.exit_code == 1 and "anchor mismatch" in forged.output

        malformed = runner.invoke(app, ["verify", str(store.path), "--expect-head", "nope"])
        assert malformed.exit_code == 2


class TestReadOnly:
    def test_append_is_refused(self, tmp_path):
        rw = EvidenceStore(tmp_path / "e.db")
        rw.append(session_id="s", app="t", event_type=EventType.LLM_REQUEST, payload={})
        rw.close()
        ro = EvidenceStore(tmp_path / "e.db", read_only=True)
        try:
            with pytest.raises(RuntimeError, match="read-only"):
                ro.append(session_id="s", app="t", event_type=EventType.LLM_REQUEST, payload={})
        finally:
            ro.close()

    def test_reads_and_verifies_read_only(self, tmp_path):
        rw = EvidenceStore(tmp_path / "e.db")
        fill(rw, 4)
        rw.close()
        ro = EvidenceStore(tmp_path / "e.db", read_only=True)
        try:
            assert len(list(ro.events())) == 4
            assert ro.verify().ok
        finally:
            ro.close()


class TestGetEvent:
    def test_get_event_found_and_missing(self, store):
        events = fill(store, 3)
        got = store.get_event(events[1].event_id)
        assert got == events[1]
        assert store.get_event("nope") is None
