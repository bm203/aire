"""Assemble an AuditReport from stored evidence.

Reads finding and policy.result events (the outputs of `aire detect` and
`aire evaluate`), resolves framework refs to citations, computes session risk
scores, and verifies the chain. The report never says "compliant" — it says
finding → evidence pointer → framework citation, and leaves judgment to the
auditor.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path

import aire
from aire.core.events import AuditEvent, EventType
from aire.core.types import Severity
from aire.mappings import FrameworkMappings
from aire.report.models import AuditReport, ChainStatus, ReportFinding, SessionReport
from aire.risk import score_to_level, weight_for
from aire.store import EvidenceStore

# Recommendations keyed by origin prefix — deliberately generic remediation
# direction; specifics belong to the organization's own processes.
_RECOMMENDATIONS: dict[str, str] = {
    "memory.retention_deletion": (
        "Verify the memory stack's deletion and retention behavior; erasure requests "
        "must remove checkpointer rows, and retention limits need automated enforcement."
    ),
    "pii.content": (
        "Minimize personal data entering prompts and memory; consider redaction before "
        "persistence and a data-minimization review of the conversation design."
    ),
    "prompt_injection.heuristic": (
        "Review flagged interactions for injection; treat tool results and retrieved "
        "content as untrusted inputs and consider allowlisting tool arguments."
    ),
    "audit_log.completeness": (
        "Investigate evidence gaps: dropped events, unmatched requests, or chain breaks "
        "reduce what this audit can attest to."
    ),
    "TOOL_": "Review tool governance: align the deployed tool set with the approved allowlist.",
    "MODEL_": "Align deployed models with the organization's approved model inventory.",
    "SESSION_": "Ensure every AI interaction is attributed to a session for traceability.",
}


def build_report(
    store: EvidenceStore,
    *,
    mappings: FrameworkMappings | None = None,
    session_id: str | None = None,
    title: str = "AIRE Audit Report",
) -> AuditReport:
    mappings = mappings or FrameworkMappings.load()

    verification = store.verify()
    chain = ChainStatus(
        ok=verification.ok,
        events_verified=verification.checked,
        first_bad_seq=verification.first_bad_seq,
        reason=verification.reason,
    )

    all_events = list(store.events(session_id=session_id))
    findings: list[ReportFinding] = []
    for event in all_events:
        if event.event_type is EventType.FINDING and event.payload.get("detector_id"):
            findings.append(_from_finding(event, mappings))
        elif event.event_type is EventType.POLICY_RESULT and event.payload.get("policy_id"):
            findings.append(_from_policy_result(event, mappings))

    by_session: dict[str, list[ReportFinding]] = defaultdict(list)
    for finding in findings:
        by_session[finding.session_id].append(finding)

    sessions = []
    for sid in sorted(by_session):
        session_findings = sorted(
            by_session[sid], key=lambda f: (-f.risk_contribution, f.ts, f.record_event_id)
        )
        score = round(sum(f.risk_contribution for f in session_findings), 2)
        sessions.append(
            SessionReport(
                session_id=sid,
                risk_score=score,
                risk_level=score_to_level(score),
                findings=session_findings,
            )
        )

    overall_score = round(sum(s.risk_score for s in sessions), 2)
    severity_totals = Counter(f.severity.value for f in findings)
    # A broken chain caps everything: the report itself becomes suspect.
    overall_level = score_to_level(overall_score)
    if not chain.ok:
        overall_level = score_to_level(float("inf"))

    recommendations = sorted(
        {
            text
            for finding in findings
            for prefix, text in _RECOMMENDATIONS.items()
            if finding.origin.startswith(prefix)
        }
    )
    if not chain.ok:
        recommendations.insert(
            0,
            "URGENT: the evidence chain is broken — investigate tampering or corruption "
            "before relying on any other result in this report.",
        )

    return AuditReport(
        title=title,
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        aire_version=aire.__version__,
        store_path=str(Path(store.path).name),  # basename only: no host paths in reports
        session_filter=session_id,
        chain=chain,
        total_events=len(all_events),
        overall_risk_score=overall_score,
        overall_risk_level=overall_level,
        severity_totals=dict(severity_totals),
        sessions=sessions,
        recommendations=recommendations,
    )


def _from_finding(event: AuditEvent, mappings: FrameworkMappings) -> ReportFinding:
    p = event.payload
    severity = Severity(p.get("severity", "medium"))
    citations, unknown = mappings.resolve(p.get("framework_refs", []))
    return ReportFinding(
        kind="finding",
        origin=p.get("detector_id", "unknown"),
        severity=severity,
        summary=p.get("summary", ""),
        session_id=event.session_id,
        ts=event.ts,
        record_event_id=event.event_id,
        record_event_hash=event.hash,
        source_event_ids=p.get("source_event_ids", []),
        source_event_hashes=p.get("source_event_hashes", []),
        citations=citations,
        unresolved_refs=unknown,
        risk_contribution=weight_for(severity),
        detail=p.get("detail", {}),
    )


def _from_policy_result(event: AuditEvent, mappings: FrameworkMappings) -> ReportFinding:
    p = event.payload
    severity = Severity(p.get("severity", "medium"))
    verdict = p.get("verdict", "fail")
    citations, unknown = mappings.resolve(p.get("framework_refs", []))
    # error verdicts describe coverage gaps, not violations — no risk weight
    contribution = 0.0 if verdict == "error" else weight_for(severity, warn=(verdict == "warn"))
    return ReportFinding(
        kind="policy_violation",
        origin=p.get("policy_id", "unknown"),
        severity=severity,
        verdict=verdict,
        summary=p.get("explanation", ""),
        session_id=event.session_id,
        ts=event.ts,
        record_event_id=event.event_id,
        record_event_hash=event.hash,
        source_event_ids=[p["source_event_id"]] if p.get("source_event_id") else [],
        source_event_hashes=[p["source_event_hash"]] if p.get("source_event_hash") else [],
        citations=citations,
        unresolved_refs=unknown,
        risk_contribution=contribution,
    )
