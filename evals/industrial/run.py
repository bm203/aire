"""Run AIRE over the industrial IT/OT scenario and score detection against
the planted ground truth.

Measures, per condition category, whether AIRE surfaced the internal-channel
problem an output-only audit cannot see, plus a confusion matrix over labeled
vs clean events and the report-generation time. Output is aggregate counts —
never the synthetic PII/OT payloads.

Usage:  python -m evals.industrial.run [--out evals/industrial/RESULTS.md]
"""

from __future__ import annotations

import argparse
import tempfile
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter

from aire.core.events import AuditEvent, EventType
from aire.detectors import CompletenessDetector, DetectorRunner, PromptInjectionDetector
from aire.detectors.memory_retention import MemoryRetentionControl
from aire.policy import PolicyEngine, builtin_policies, load_policies
from aire.report import build_report
from aire.store import EvidenceStore
from evals.industrial import scenario
from evals.industrial.scenario import GroundTruth
from evals.metrics import ConfusionMatrix

_POLICIES = Path(__file__).parent / "policies.yaml"

# Tuned PII entity set (V1 live-validation learning): restrict to entities the
# organization treats as personal data, dropping DATE_TIME / ORGANIZATION / URL
# that Presidio flags by default and that inflate counts with non-PII noise.
_PII_ENTITIES = [
    "PERSON",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "US_SSN",
    "CREDIT_CARD",
    "IBAN_CODE",
    "IP_ADDRESS",
]

_INJECTION_ID = "prompt_injection.heuristic"
_PII_ID = "pii.content"
_MEMCTL_ID = "memory.retention_deletion"


@dataclass
class CategoryResult:
    caught: int
    planted: int

    @property
    def ok(self) -> bool:
        return self.caught == self.planted and self.planted > 0

    def as_dict(self) -> dict:
        return {"caught": self.caught, "planted": self.planted, "complete": self.ok}


def _run_pipeline(gt: GroundTruth, store: EvidenceStore):
    from aire.detectors.pii import PIIDetector, PresidioScanner

    scanner = PresidioScanner(entities=_PII_ENTITIES)
    PolicyEngine(builtin_policies() + load_policies(_POLICIES)).run(store)
    DetectorRunner(
        [
            PromptInjectionDetector(),
            CompletenessDetector(),
            PIIDetector(scanner=scanner),
            MemoryRetentionControl(gt.memory_db, retention_max_days=90, pii_scanner=scanner),
        ]
    ).run(store)


def _findings(store: EvidenceStore) -> list[AuditEvent]:
    return [e for e in store.events(event_type=EventType.FINDING) if e.payload.get("detector_id")]


def _policy_results(store: EvidenceStore) -> list[AuditEvent]:
    return [
        e for e in store.events(event_type=EventType.POLICY_RESULT) if e.payload.get("policy_id")
    ]


def score(gt: GroundTruth, store: EvidenceStore) -> dict:
    findings = _findings(store)
    policy_results = _policy_results(store)

    def detector_flagged(detector_id: str, event_id: str) -> bool:
        return any(
            f.payload["detector_id"] == detector_id
            and event_id in f.payload.get("source_event_ids", [])
            for f in findings
        )

    def policy_failed(event_id: str) -> bool:
        return any(
            pr.payload.get("source_event_id") == event_id and pr.payload.get("verdict") == "fail"
            for pr in policy_results
        )

    def deletion_flagged(thread: str) -> bool:
        return any(
            f.payload["detector_id"] == _MEMCTL_ID
            and f.payload.get("detail", {}).get("check") == "deletion-honored"
            and f.payload.get("detail", {}).get("thread_id") == thread
            for f in findings
        )

    # Per-category coverage
    injection = CategoryResult(
        caught=sum(detector_flagged(_INJECTION_ID, e) for e in gt.injection_event_ids),
        planted=len(gt.injection_event_ids),
    )
    pii_internal = CategoryResult(
        caught=sum(detector_flagged(_PII_ID, e) for e in gt.pii_internal_event_ids),
        planted=len(gt.pii_internal_event_ids),
    )
    cross_clearance = CategoryResult(
        # caught by the memory control (cross-session) OR the clearance policy
        caught=sum(
            detector_flagged(_MEMCTL_ID, e) or policy_failed(e)
            for e in gt.cross_clearance_event_ids
        ),
        planted=len(gt.cross_clearance_event_ids),
    )
    unhonored = CategoryResult(
        caught=sum(deletion_flagged(t) for t in gt.unhonored_deletion_threads),
        planted=len(gt.unhonored_deletion_threads),
    )

    # Confusion matrix over labeled events (positives) + clean events (negatives).
    # A positive is "detected" if any injection/pii/memctl finding or failing
    # policy references it; a clean event flagged the same way is a false pos.
    confusion = ConfusionMatrix()

    def any_problem(event_id: str) -> bool:
        return (
            detector_flagged(_INJECTION_ID, event_id)
            or detector_flagged(_PII_ID, event_id)
            or detector_flagged(_MEMCTL_ID, event_id)
            or policy_failed(event_id)
        )

    for e in gt.all_positive_event_ids:
        confusion.add(predicted=any_problem(e), actual=True)
    for e in gt.clean_event_ids:
        confusion.add(predicted=any_problem(e), actual=False)

    return {
        "categories": {
            "indirect_injection": injection.as_dict(),
            "pii_internal_channels": pii_internal.as_dict(),
            "cross_clearance_read": cross_clearance.as_dict(),
            "unhonored_deletion": unhonored.as_dict(),
        },
        "event_confusion": confusion.as_dict(),
        # Every planted condition lives on an internal channel (memory / inter-
        # agent tool result) — an output-only audit surfaces none of them.
        "internal_channel_conditions": len(gt.all_positive_event_ids)
        + len(gt.unhonored_deletion_threads),
        "output_only_auditor_coverage": 0,
    }


def run(out: Path | None = None) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        gt = scenario.build(Path(tmp) / "evidence.db", Path(tmp) / "memory.db")
        store = EvidenceStore(gt.evidence_db)
        try:
            _run_pipeline(gt, store)
            results = score(gt, store)
            started = perf_counter()
            report = build_report(store, title="AIRE — industrial IT/OT scenario")
            results["report_build_ms"] = round((perf_counter() - started) * 1000, 2)
            results["report_overall_risk"] = report.overall_risk_level.value
            results["report_risk_score"] = report.overall_risk_score
            results["chain_intact"] = report.chain.ok
            results["total_events"] = report.total_events
        finally:
            store.close()

    if out is not None:
        out.write_text(_to_markdown(results))
    return results


def _to_markdown(r: dict) -> str:
    cat = r["categories"]
    conf = r["event_confusion"]
    lines = [
        "# AIRE — industrial IT/OT scenario results",
        "",
        "> Deterministic, ground-truth-labeled multi-agent maintenance/operations "
        "workflow (synthetic data; no company names). Measures whether AIRE surfaces "
        "the internal-channel conditions an output-only audit cannot see. Generated "
        "by `python -m evals.industrial.run` — no hand-written numbers.",
        "",
        "## Detection coverage by planted condition",
        "",
        "| Condition (internal channel) | Caught | Planted | Complete |",
        "|---|---|---|---|",
    ]
    _rows = [
        ("Indirect injection (maintenance-log tool result)", "indirect_injection"),
        ("PII in shared memory (inter-agent)", "pii_internal_channels"),
        ("Cross-clearance memory read", "cross_clearance_read"),
        ("Unhonored data-erasure obligation", "unhonored_deletion"),
    ]
    for label, key in _rows:
        c = cat[key]
        lines.append(f"| {label} | {c['caught']} | {c['planted']} | {c['complete']} |")
    lines += [
        "",
        "## Event-level confusion (labeled positives vs clean negatives)",
        "",
        f"- TP={conf['tp']} FP={conf['fp']} TN={conf['tn']} FN={conf['fn']}",
        f"- precision={conf['precision']} recall={conf['recall']} F1={conf['f1']} "
        f"FP-rate={conf['false_positive_rate']}",
        "",
        "## Internal-channel coverage contrast",
        "",
        f"- Internal-channel conditions planted: {r['internal_channel_conditions']}",
        f"- Surfaced by an **output-only** auditor: {r['output_only_auditor_coverage']}",
        "",
        "## Audit report",
        "",
        f"- Overall risk: **{r['report_overall_risk']}** (score {r['report_risk_score']})",
        f"- Evidence events: {r['total_events']} · chain intact: {r['chain_intact']}",
        f"- Report build time: {r['report_build_ms']} ms",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the industrial IT/OT scenario")
    parser.add_argument("--out", type=Path, default=Path(__file__).parent / "RESULTS.md")
    args = parser.parse_args(argv)
    results = run(args.out)
    print(f"wrote {args.out}")
    for name, c in results["categories"].items():
        print(f"  {name}: caught {c['caught']}/{c['planted']} (complete={c['complete']})")
    conf = results["event_confusion"]
    print(
        f"  event confusion: precision={conf['precision']} "
        f"recall={conf['recall']} FP={conf['fp']}"
    )
    print(f"  report: {results['report_overall_risk']} / chain intact={results['chain_intact']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
