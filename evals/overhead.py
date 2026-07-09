"""Evidence-store overhead and report-generation timing.

Measures the cost AIRE adds: per-event append latency (the hash-chain +
SQLite write in the sensor path) and end-to-end report build time. Uses a
temporary store so nothing persists.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from time import perf_counter

from aire.core.events import EventType
from aire.store import EvidenceStore
from evals.metrics import LatencySamples


def measure_append_overhead(n: int = 2000) -> dict:
    latency = LatencySamples()
    with tempfile.TemporaryDirectory() as tmp:
        store = EvidenceStore(Path(tmp) / "overhead.db")
        try:
            for i in range(n):
                started = perf_counter()
                store.append(
                    session_id="overhead",
                    app="eval.overhead",
                    event_type=EventType.LLM_REQUEST,
                    payload={"i": i, "messages": [{"role": "user", "content": "sample prompt"}]},
                )
                latency.record((perf_counter() - started) * 1000)
        finally:
            store.close()
    return {"events_appended": n, "append_latency": latency.as_dict()}


def measure_report_time(n_events: int = 500) -> dict:
    from aire.detectors import CompletenessDetector, DetectorRunner, PromptInjectionDetector
    from aire.policy import PolicyEngine, builtin_policies
    from aire.report import build_report

    with tempfile.TemporaryDirectory() as tmp:
        store = EvidenceStore(Path(tmp) / "report.db")
        try:
            for i in range(n_events):
                store.append(
                    session_id=f"s-{i % 10}",
                    app="eval.overhead",
                    event_type=EventType.TOOL_CALL,
                    payload={"gen_ai.tool.name": "lookup_order" if i % 3 else "unapproved"},
                )
            PolicyEngine(builtin_policies()).run(store)
            DetectorRunner([PromptInjectionDetector(), CompletenessDetector()]).run(store)

            started = perf_counter()
            report = build_report(store)
            build_ms = (perf_counter() - started) * 1000
        finally:
            store.close()
    return {
        "events_in_store": report.total_events,
        "sessions": len(report.sessions),
        "report_build_ms": round(build_ms, 3),
    }
