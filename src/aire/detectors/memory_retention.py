"""Deep control: memory retention & deletion verification (LangGraph checkpointer).

The question an auditor actually asks about AI memory is not "was deletion
requested?" but **"is the data actually gone?"**. This control answers it by
cross-examining two independent sources:

1. the AIRE evidence chain (what the app *claimed*: memory.write/read/delete
   events recorded by the collector), and
2. the LangGraph checkpointer database itself (what is *actually stored*),
   opened strictly read-only (``mode=ro`` SQLite URI — the host app's data
   is never touched; a write attempt would fail at the SQLite level).

Checks:

- **deletion-honored** (critical): a recorded ``memory.delete`` for a thread,
  no subsequent re-write, yet checkpoints/writes rows still exist for it.
- **retention-exceeded** (high): surviving checkpoints older than the
  configured maximum age.
- **pii-in-memory** (high): personal data present in the latest surviving
  checkpoint of a thread (via the pluggable PII scanner — Presidio in prod).
- **cross-session-read** (medium): a session read another session's memory.

Checkpoint blobs are parsed by the checkpointer's own serde (via
``SqliteSaver.get_tuple``/``list``) — never by homegrown blob parsing.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

try:
    from langgraph.checkpoint.sqlite import SqliteSaver
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "aire.detectors.memory_retention requires the 'langgraph' extra: "
        "pip install 'aire[langgraph]'"
    ) from exc

from aire.core.events import AuditEvent, EventType
from aire.core.types import Severity
from aire.detectors.base import Detector, Finding
from aire.detectors.pii import PIIScanner
from aire.store import EvidenceStore

_REFS_DELETION = ["EU-AI-ACT:Art.10", "NIST-AI-RMF:MEASURE-2.10", "OWASP-LLM:LLM02"]
_REFS_RETENTION = ["EU-AI-ACT:Art.10", "NIST-AI-RMF:MEASURE-2.10"]
_REFS_PII = ["EU-AI-ACT:Art.10", "OWASP-LLM:LLM02", "ISO42001:A.5.4"]
_REFS_XSESSION = ["OWASP-LLM:LLM02", "EU-AI-ACT:Art.10"]

_UNATTRIBUTED = "unattributed"


class MemoryRetentionControl(Detector):
    id = "memory.retention_deletion"

    def __init__(
        self,
        memory_db: str | Path,
        *,
        retention_max_days: float | None = None,
        pii_scanner: PIIScanner | None = None,
        now: datetime | None = None,
    ) -> None:
        self.memory_db = Path(memory_db)
        self.retention_max_days = retention_max_days
        self.pii_scanner = pii_scanner
        self._now = now  # injectable for tests

    def inspect(self, events: list[AuditEvent], store: EvidenceStore) -> list[Finding]:
        if not self.memory_db.exists():
            return [
                Finding(
                    detector_id=self.id,
                    severity=Severity.MEDIUM,
                    summary=f"memory database not found at {self.memory_db} — control did not run",
                    dedupe_key=f"missing-db:{self.memory_db}",
                    framework_refs=_REFS_RETENTION,
                )
            ]
        conn = self._open_readonly()
        try:
            saver = SqliteSaver(conn)
            saver.is_setup = True  # never run DDL — the connection is read-only anyway
            findings = []
            findings += self._check_deletions(events, conn)
            findings += self._check_retention(conn, saver)
            findings += self._check_pii(conn, saver)
            findings += self._check_cross_session_reads(events)
            return findings
        finally:
            conn.close()

    # -- helpers -------------------------------------------------------------

    def _open_readonly(self) -> sqlite3.Connection:
        return sqlite3.connect(f"file:{self.memory_db}?mode=ro", uri=True)

    def _threads(self, conn: sqlite3.Connection) -> list[str]:
        if not conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='checkpoints'"
        ).fetchone():
            return []
        return [r[0] for r in conn.execute("SELECT DISTINCT thread_id FROM checkpoints")]

    @staticmethod
    def _surviving_rows(conn: sqlite3.Connection, thread_id: str) -> dict[str, int]:
        counts = {}
        for table in ("checkpoints", "writes"):
            if conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
            ).fetchone():
                counts[table] = conn.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE thread_id=?", (thread_id,)  # noqa: S608
                ).fetchone()[0]
        return counts

    @staticmethod
    def _config(thread_id: str) -> dict:
        return {"configurable": {"thread_id": thread_id, "checkpoint_ns": ""}}

    # -- checks ---------------------------------------------------------------

    def _check_deletions(
        self, events: list[AuditEvent], conn: sqlite3.Connection
    ) -> list[Finding]:
        findings = []
        # Chain order == time order: a later write to the same thread makes
        # surviving data legitimate (the app re-created memory after erasure).
        for i, event in enumerate(events):
            if event.event_type is not EventType.MEMORY_DELETE:
                continue
            thread_id = event.payload.get("thread_id")
            if not thread_id:
                continue
            rewritten = any(
                later.event_type is EventType.MEMORY_WRITE
                and later.payload.get("thread_id") == thread_id
                for later in events[i + 1 :]
            )
            if rewritten:
                continue
            surviving = self._surviving_rows(conn, thread_id)
            total = sum(surviving.values())
            if total > 0:
                findings.append(
                    Finding(
                        detector_id=self.id,
                        severity=Severity.CRITICAL,
                        summary=(
                            f"deletion NOT honored: memory.delete was recorded for "
                            f"thread '{thread_id}' but {total} row(s) still exist in "
                            "the checkpointer database"
                        ),
                        detail={
                            "check": "deletion-honored",
                            "thread_id": thread_id,
                            "surviving_rows": surviving,
                            "delete_event_ts": event.ts,
                        },
                        dedupe_key=f"deletion:{thread_id}:{event.event_id}",
                        session_id=event.session_id,
                        source_event_ids=[event.event_id],
                        source_event_hashes=[event.hash],
                        framework_refs=_REFS_DELETION,
                    )
                )
        return findings

    def _check_retention(self, conn: sqlite3.Connection, saver: SqliteSaver) -> list[Finding]:
        if self.retention_max_days is None:
            return []
        now = self._now or datetime.now(UTC)
        cutoff = now - timedelta(days=self.retention_max_days)
        findings = []
        for thread_id in self._threads(conn):
            oldest_ts: datetime | None = None
            count = 0
            for ckpt_tuple in saver.list(self._config(thread_id)):
                count += 1
                ts = _parse_ts(ckpt_tuple.checkpoint.get("ts"))
                if ts and (oldest_ts is None or ts < oldest_ts):
                    oldest_ts = ts
            if oldest_ts and oldest_ts < cutoff:
                age_days = (now - oldest_ts).days
                findings.append(
                    Finding(
                        detector_id=self.id,
                        severity=Severity.HIGH,
                        summary=(
                            f"retention exceeded: thread '{thread_id}' holds a checkpoint "
                            f"{age_days} day(s) old (policy maximum: "
                            f"{self.retention_max_days} day(s))"
                        ),
                        detail={
                            "check": "retention-exceeded",
                            "thread_id": thread_id,
                            "oldest_checkpoint_ts": oldest_ts.isoformat(),
                            "age_days": age_days,
                            "max_days": self.retention_max_days,
                            "checkpoints": count,
                        },
                        dedupe_key=f"retention:{thread_id}",
                        session_id=thread_id,
                        framework_refs=_REFS_RETENTION,
                    )
                )
        return findings

    def _check_pii(self, conn: sqlite3.Connection, saver: SqliteSaver) -> list[Finding]:
        if self.pii_scanner is None:
            return []
        findings = []
        for thread_id in self._threads(conn):
            latest = saver.get_tuple(self._config(thread_id))
            if latest is None:
                continue
            text = json.dumps(latest.checkpoint.get("channel_values", {}), default=str)
            matches = self.pii_scanner.scan(text)
            if not matches:
                continue
            entity_counts: dict[str, int] = {}
            for m in matches:
                entity_counts[m.entity_type] = entity_counts.get(m.entity_type, 0) + 1
            summary_counts = ", ".join(f"{t}×{n}" for t, n in sorted(entity_counts.items()))
            findings.append(
                Finding(
                    detector_id=self.id,
                    severity=Severity.HIGH,
                    summary=(
                        f"personal data stored in memory: thread '{thread_id}' latest "
                        f"checkpoint contains {summary_counts}"
                    ),
                    # types + counts only — never the values themselves
                    detail={
                        "check": "pii-in-memory",
                        "thread_id": thread_id,
                        "checkpoint_id": latest.checkpoint.get("id"),
                        "entity_counts": entity_counts,
                    },
                    dedupe_key=f"memory-pii:{thread_id}:{latest.checkpoint.get('id')}",
                    session_id=thread_id,
                    framework_refs=_REFS_PII,
                )
            )
        return findings

    def _check_cross_session_reads(self, events: list[AuditEvent]) -> list[Finding]:
        findings = []
        for event in events:
            if event.event_type is not EventType.MEMORY_READ:
                continue
            thread_id = event.payload.get("thread_id")
            session_id = event.session_id
            if not thread_id or session_id in (thread_id, _UNATTRIBUTED):
                continue
            findings.append(
                Finding(
                    detector_id=self.id,
                    severity=Severity.MEDIUM,
                    summary=(
                        f"cross-session memory access: session '{session_id}' read "
                        f"memory of thread '{thread_id}'"
                    ),
                    detail={
                        "check": "cross-session-read",
                        "thread_id": thread_id,
                        "reader_session": session_id,
                    },
                    dedupe_key=f"xsession:{event.event_id}",
                    session_id=session_id,
                    source_event_ids=[event.event_id],
                    source_event_hashes=[event.hash],
                    framework_refs=_REFS_XSESSION,
                )
            )
        return findings


def _parse_ts(value) -> datetime | None:
    try:
        ts = datetime.fromisoformat(str(value))
        return ts if ts.tzinfo else ts.replace(tzinfo=UTC)
    except (ValueError, TypeError):
        return None
