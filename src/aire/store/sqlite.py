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
import sqlite3
import threading
from collections.abc import Iterator
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
"""

_COLUMNS = "event_id, ts, session_id, trace_id, app, event_type, payload, prev_hash, hash"


@dataclass
class VerificationResult:
    ok: bool
    checked: int
    first_bad_seq: int | None = None
    first_bad_event_id: str | None = None
    reason: str | None = None


class EvidenceStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
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

    def append(
        self,
        *,
        session_id: str,
        app: str,
        event_type: EventType,
        payload: dict[str, Any] | None = None,
        trace_id: str | None = None,
    ) -> AuditEvent:
        """Seal an event onto the chain head and persist it atomically."""
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

    def head_hash(self) -> str:
        row = self._conn.execute("SELECT hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        return row[0] if row else GENESIS_HASH

    def verify(self) -> VerificationResult:
        """Walk the full chain; report the first broken link, if any."""
        expected_prev = GENESIS_HASH
        checked = 0
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
            expected_prev = event.hash
            checked += 1
        return VerificationResult(ok=True, checked=checked)

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
