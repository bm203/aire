"""Append-only, hash-chained evidence store on SQLite.

Two independent integrity layers:

1. **Append-only at the database level** — triggers abort any UPDATE or
   DELETE on the events table. This stops accidental mutation through the
   normal write path.
2. **Hash chain** — each stored event carries the previous event's hash and
   its own hash over its canonical body. An attacker with file access can
   drop the triggers and edit rows, but cannot do so without breaking the
   chain, which :meth:`EvidenceStore.verify` detects and localizes.
"""

from __future__ import annotations

import json
import re
import sqlite3
import threading
import uuid
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aire.core.events import GENESIS_HASH, AuditEvent, EventType

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id   TEXT NOT NULL UNIQUE,
    ts         TEXT NOT NULL,
    session_id TEXT NOT NULL,
    trace_id   TEXT,
    app        TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload    TEXT NOT NULL,
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
BEGIN SELECT RAISE(ABORT, 'evidence log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
BEGIN SELECT RAISE(ABORT, 'evidence log is append-only'); END;
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS meta_no_update BEFORE UPDATE ON meta
BEGIN SELECT RAISE(ABORT, 'store metadata is immutable'); END;
CREATE TRIGGER IF NOT EXISTS meta_no_delete BEFORE DELETE ON meta
BEGIN SELECT RAISE(ABORT, 'store metadata is immutable'); END;
"""

_COLUMNS = "event_id, ts, session_id, trace_id, app, event_type, payload, prev_hash, hash"


_ANCHOR = re.compile(r"(\d+):([0-9a-f]{64})")


@dataclass
class VerificationResult:
    ok: bool
    checked: int
    first_bad_seq: int | None = None
    first_bad_event_id: str | None = None
    reason: str | None = None
    # The chain head after a successful walk, as ``seq:hash``. Recording it
    # somewhere the store's writer cannot reach turns internal consistency into
    # tamper evidence for everything up to that point (see ``verify``).
    head: str | None = None
    anchor_checked: bool = False


# Called with the store path before reads. The background writer registers one
# so a process reading a store it is also writing to sees its own pending events.
_read_hooks: list[Callable[[str], None]] = []


def register_read_hook(hook: Callable[[str], None]) -> None:
    if hook not in _read_hooks:
        _read_hooks.append(hook)


def parse_anchor(anchor: str) -> tuple[int, str]:
    """Parse a recorded head of the form ``seq:hash``."""
    m = _ANCHOR.fullmatch(anchor.strip().lower())
    if not m:
        raise ValueError(f"anchor must look like <seq>:<64 hex chars>, got {anchor!r}")
    return int(m.group(1)), m.group(2)


class EvidenceStore:
    def __init__(self, path: str | Path, *, read_only: bool = False) -> None:
        self.path = Path(path)
        self.read_only = read_only
        self._lock = threading.Lock()
        if read_only:
            # A viewer (e.g. the dashboard) opens the store OS-level read-only:
            # no schema DDL, no chmod, and append() is refused. The evidence is
            # never mutated by anything that only reads it.
            self._conn = sqlite3.connect(
                f"file:{self.path}?mode=ro", uri=True, check_same_thread=False
            )
        else:
            self._conn = sqlite3.connect(self.path, check_same_thread=False)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(_SCHEMA)
            # A store's identity is fixed at creation (or the first read-write
            # open of a store that predates it). Checkpoints name it, so a
            # checkpoint for one store cannot be replayed against another.
            self._conn.execute(
                "INSERT OR IGNORE INTO meta (key, value) VALUES ('store_id', ?)",
                (str(uuid.uuid4()),),
            )
            self._conn.commit()
            self._restrict_permissions()

    def _restrict_permissions(self) -> None:
        """Evidence contains prompts, memory contents, and possibly PII —
        owner-only access on the DB file and its WAL/SHM sidecars."""
        for suffix in ("", "-wal", "-shm"):
            sidecar = Path(str(self.path) + suffix)
            try:
                if sidecar.exists():
                    sidecar.chmod(0o600)
            except OSError:
                pass  # best effort; never break the host over perms

    def close(self) -> None:
        self._conn.close()

    def _before_read(self) -> None:
        for hook in _read_hooks:
            try:
                hook(str(self.path))
            except Exception:  # a hook must never break a read
                pass

    def append(
        self,
        *,
        session_id: str,
        app: str,
        event_type: EventType,
        payload: dict[str, Any] | None = None,
        trace_id: str | None = None,
        ts: str | None = None,
    ) -> AuditEvent:
        """Seal an event onto the chain head and persist it atomically.

        ``ts`` is when the event was observed; it defaults to now. The
        background writer passes the time captured on the host thread.
        """
        if self.read_only:
            raise RuntimeError("evidence store opened read-only; append is refused")
        with self._lock:
            # BEGIN IMMEDIATE takes the write lock before reading the chain
            # head, so head lookup + insert are one atomic unit even with
            # multiple store instances on the same file.
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT hash FROM events ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                prev_hash = row[0] if row else GENESIS_HASH
                event = AuditEvent(
                    **({"ts": ts} if ts is not None else {}),
                    session_id=session_id,
                    trace_id=trace_id,
                    app=app,
                    event_type=event_type,
                    payload=payload or {},
                    prev_hash=prev_hash,
                ).sealed()
                self._conn.execute(
                    f"INSERT INTO events ({_COLUMNS}) VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        event.event_id,
                        event.ts,
                        event.session_id,
                        event.trace_id,
                        event.app,
                        event.event_type.value,
                        json.dumps(event.payload, sort_keys=True, ensure_ascii=False),
                        event.prev_hash,
                        event.hash,
                    ),
                )
                self._conn.commit()
            except BaseException:
                self._conn.rollback()
                raise
        return event

    def events(
        self,
        *,
        session_id: str | None = None,
        event_type: EventType | None = None,
    ) -> Iterator[AuditEvent]:
        """Yield stored events in chain order, optionally filtered."""
        self._before_read()
        query = f"SELECT {_COLUMNS} FROM events"
        clauses, params = [], []
        if session_id is not None:
            clauses.append("session_id = ?")
            params.append(session_id)
        if event_type is not None:
            clauses.append("event_type = ?")
            params.append(event_type.value)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY seq"
        for row in self._conn.execute(query, params):
            yield self._row_to_event(row)

    def get_event(self, event_id: str) -> AuditEvent | None:
        """Return one event by id, or None (used by the dashboard drill-down)."""
        self._before_read()
        row = self._conn.execute(
            f"SELECT {_COLUMNS} FROM events WHERE event_id = ?", (event_id,)
        ).fetchone()
        return self._row_to_event(row) if row else None

    def store_id(self) -> str | None:
        """The store's fixed identity, or None for a store that predates it."""
        try:
            row = self._conn.execute("SELECT value FROM meta WHERE key = 'store_id'").fetchone()
        except sqlite3.OperationalError:  # read-only open of a store without a meta table
            return None
        return row[0] if row else None

    def head_hash(self) -> str:
        self._before_read()
        row = self._conn.execute("SELECT hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        return row[0] if row else GENESIS_HASH

    def verify(
        self, expect_head: str | None = None, *, anchors: Iterable[str] = ()
    ) -> VerificationResult:
        """Walk the full chain; report the first broken link, if any.

        Without ``expect_head`` this proves the chain is internally consistent:
        it catches accidental edits and naive tampering. It cannot catch someone
        with write access who rewrites events and recomputes every later hash,
        because the chain uses no secret. ``expect_head`` closes that gap up to
        a recorded point: pass a head (``seq:hash``) printed by an earlier
        verification and stored outside the writer's reach. Any rewrite,
        removal, or reordering at or before that point then fails, while events
        appended afterwards still verify normally.

        ``anchors`` checks several recorded heads in the same single walk (used
        for checkpoint files).
        """
        self._before_read()
        expected: dict[int, str] = {}
        for raw in [*anchors, *([expect_head] if expect_head is not None else [])]:
            seq, hash_ = parse_anchor(raw)
            if expected.get(seq, hash_) != hash_:
                raise ValueError(f"conflicting anchors for seq {seq}")
            expected[seq] = hash_
        expected_prev = GENESIS_HASH
        checked = 0
        head: str | None = None
        seen: set[int] = set()
        for seq, *row in self._conn.execute(
            f"SELECT seq, {_COLUMNS} FROM events ORDER BY seq"
        ):
            event = self._row_to_event(row)
            if event.prev_hash != expected_prev:
                return VerificationResult(
                    ok=False,
                    checked=checked,
                    first_bad_seq=seq,
                    first_bad_event_id=event.event_id,
                    reason=(
                        "chain break: prev_hash does not match the preceding "
                        "event's hash (event inserted, removed, or reordered)"
                    ),
                )
            if not event.is_intact():
                return VerificationResult(
                    ok=False,
                    checked=checked,
                    first_bad_seq=seq,
                    first_bad_event_id=event.event_id,
                    reason="content tamper: stored hash does not match recomputed hash",
                )
            if seq in expected:
                if event.hash != expected[seq]:
                    return VerificationResult(
                        ok=False,
                        checked=checked,
                        first_bad_seq=seq,
                        first_bad_event_id=event.event_id,
                        reason=(
                            "anchor mismatch: the event at the recorded head differs "
                            "from the recorded hash (history up to this point was rewritten)"
                        ),
                    )
                seen.add(seq)
            expected_prev = event.hash
            head = f"{seq}:{event.hash}"
            checked += 1
        missing = sorted(set(expected) - seen)
        if missing:
            return VerificationResult(
                ok=False,
                checked=checked,
                first_bad_seq=missing[0],
                reason=(
                    "anchor not found: no event exists at the recorded head "
                    "(events were removed or renumbered)"
                ),
            )
        return VerificationResult(
            ok=True, checked=checked, head=head, anchor_checked=bool(expected)
        )

    @staticmethod
    def _row_to_event(row: sqlite3.Row | tuple) -> AuditEvent:
        event_id, ts, session_id, trace_id, app, event_type, payload, prev_hash, hash_ = row
        return AuditEvent(
            event_id=event_id,
            ts=ts,
            session_id=session_id,
            trace_id=trace_id,
            app=app,
            event_type=EventType(event_type),
            payload=json.loads(payload),
            prev_hash=prev_hash,
            hash=hash_,
        )
