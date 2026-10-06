"""Audit report data model. JSON is the canonical format; Markdown and HTML
are renderings of this model — never independently assembled."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from aire.core.types import Severity
from aire.mappings import Citation
from aire.risk import RiskLevel


class ReportFinding(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: str  # "finding" | "policy_violation"
    origin: str  # detector id or policy id
    severity: Severity
    verdict: str | None = None  # policy results only: fail | warn | error
    summary: str
    session_id: str
    ts: str
    # Evidence pointers — the audit currency: chained event ids + hashes.
    record_event_id: str  # the finding/policy.result event itself
    record_event_hash: str
    source_event_ids: list[str] = Field(default_factory=list)
    source_event_hashes: list[str] = Field(default_factory=list)
    citations: list[Citation] = Field(default_factory=list)
    unresolved_refs: list[str] = Field(default_factory=list)
    risk_contribution: float = 0.0
    detail: dict[str, Any] = Field(default_factory=dict)


class SessionReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    session_id: str
    risk_score: float
    risk_level: RiskLevel
    findings: list[ReportFinding]


class ChainStatus(BaseModel):
    model_config = ConfigDict(frozen=True)

    ok: bool
    events_verified: int
    first_bad_seq: int | None = None
    reason: str | None = None
    # Chain head (seq:hash) when intact. A delivered report carries it out of
    # the machine, so the report itself can serve as an anchor for a later
    # `aire verify --expect-head`.
    head: str | None = None


class CoverageStatus(StrEnum):
    PASSED = "passed"  # evaluated, no failure, no evaluation error
    FAILED = "failed"  # at least one finding or failing/warning policy result
    NOT_EVALUATED = "not evaluated"  # checks errored; absence of failure proves nothing
    NO_EVIDENCE = "no evidence"  # a check covers it, but nothing applicable was recorded


class ControlCoverage(BaseModel):
    """What the evidence says about one control. Never a compliance verdict:
    PASSED means the configured checks evaluated recorded events and found no
    violation, not that the control is satisfied."""

    model_config = ConfigDict(frozen=True)

    ref: str
    framework: str
    control_id: str
    title: str
    status: CoverageStatus
    checks: list[str] = Field(default_factory=list)  # policy / detector ids covering it
    events_evaluated: int = 0
    failures: int = 0
    evaluation_errors: int = 0


class AuditReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    title: str
    generated_at: str
    aire_version: str
    store_path: str
    session_filter: str | None = None
    chain: ChainStatus
    total_events: int
    overall_risk_score: float
    overall_risk_level: RiskLevel
    severity_totals: dict[str, int]
    sessions: list[SessionReport]
    recommendations: list[str]
    # Per-control view (additive): computed for whole-store reports only.
    control_coverage: list[ControlCoverage] = Field(default_factory=list)
