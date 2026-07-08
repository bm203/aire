"""Audit-event schema and hash-chain primitives.

Every observation AIRE makes is an :class:`AuditEvent`. Events form a
tamper-evident chain: each event carries the SHA-256 hash of the previous
event (``prev_hash``) and its own hash over its canonical JSON body. Findings
and policy results are events too, so they are covered by the same chain.

Payload field names follow the OpenTelemetry GenAI semantic conventions where
an equivalent attribute exists (e.g. ``gen_ai.request.model``), so AIRE
evidence can later be exported to OTel-native backends without renaming.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from ulid import ULID

GENESIS_HASH = "0" * 64


class EventType(StrEnum):
    LLM_REQUEST = "llm.request"
    LLM_RESPONSE = "llm.response"
    TOOL_CALL = "tool.call"
    TOOL_RESULT = "tool.result"
    RETRIEVAL_CONTEXT = "retrieval.context"
    MEMORY_WRITE = "memory.write"
    MEMORY_READ = "memory.read"
    MEMORY_DELETE = "memory.delete"
    MEMORY_EXPIRE = "memory.expire"
    POLICY_RESULT = "policy.result"
    FINDING = "finding"
    SENSOR_DROPPED = "sensor.dropped"


def _new_event_id() -> str:
    # ULIDs are lexicographically sortable by creation time, which keeps
    # event ids meaningful in exports even without the store's sequence column.
    return str(ULID())


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


class AuditEvent(BaseModel):
    """One immutable observation in the evidence chain."""

    model_config = ConfigDict(frozen=True)

    event_id: str = Field(default_factory=_new_event_id)
    ts: str = Field(default_factory=_utcnow_iso)
    session_id: str
    trace_id: str | None = None
    app: str
    event_type: EventType
    payload: dict[str, Any] = Field(default_factory=dict)
    prev_hash: str = GENESIS_HASH
    hash: str = ""

    def canonical_body(self) -> str:
        """Deterministic JSON of everything except the hash itself.

        Sorted keys and fixed separators so the same event always serializes
        to the same bytes — the hash is only meaningful if this is stable.
        """
        data = self.model_dump(mode="json", exclude={"hash"})
        return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def compute_hash(self) -> str:
        return hashlib.sha256(self.canonical_body().encode("utf-8")).hexdigest()

    def sealed(self) -> AuditEvent:
        """Return a copy with ``hash`` set. Events must be sealed before storage."""
        return self.model_copy(update={"hash": self.compute_hash()})

    def is_intact(self) -> bool:
        return self.hash == self.compute_hash()
