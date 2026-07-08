"""Policy schema (the auditor-facing YAML surface) and evaluation results.

A policy is a named organizational rule. Its ``violation`` field is a CEL
expression (Common Expression Language — an industry-standard policy
expression language, NOT a homegrown DSL) evaluated per audit event. When it
evaluates true, the policy is violated and a fail/warn result is produced.

Expressions see three variables:

- ``event``   — envelope fields: event_type, session_id, app, ts, trace_id
- ``payload`` — the event payload map
- ``params``  — the policy's own ``params`` block (keeps values like
  allowlists in data rather than in the expression)
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from aire.core.events import EventType
from aire.core.types import Severity

__all__ = ["Policy", "PolicyResult", "Severity", "Verdict"]


class Verdict(StrEnum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    # The expression could not be evaluated against this event. Surfaced
    # rather than hidden: an auditor must know when coverage has gaps.
    ERROR = "error"


class Policy(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(pattern=r"^[A-Z][A-Z0-9_]{2,63}$")
    description: str
    severity: Severity
    applies_to: list[EventType] = Field(min_length=1)
    violation: str  # CEL expression; true = violated
    verdict_on_violation: Verdict = Verdict.FAIL
    params: dict[str, Any] = Field(default_factory=dict)
    framework_refs: list[str] = Field(default_factory=list)


class PolicyResult(BaseModel):
    """Outcome of evaluating one policy against one event."""

    model_config = ConfigDict(frozen=True)

    policy_id: str
    verdict: Verdict
    severity: Severity
    explanation: str
    framework_refs: list[str]
    # Evidence pointer — the currency of audits: which chained event, with
    # which hash, triggered this result.
    source_event_id: str
    source_event_hash: str
    source_session_id: str
