"""Detector infrastructure: findings, the detector interface, and the runner.

Detectors inspect evidence (out-of-band, never in the host's request path)
and emit findings. Findings are appended to the hash chain as ``finding``
events, so a finding is as tamper-evident as the evidence it points to.

Security posture (industrial use):

- All scanned content is untrusted; per-string scan size is bounded
  (:data:`MAX_SCAN_CHARS`) so adversarial payloads can't DoS an audit run.
- Findings carry evidence *pointers* and entity types/offsets — they never
  duplicate raw sensitive values out of the source event.
- A crashing detector becomes a finding itself (an auditor must know a
  control did not run), never an exception in the caller.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from aire.core.events import AuditEvent, EventType
from aire.core.types import Severity
from aire.store import EvidenceStore

_DETECT_APP = "aire.detect"
_SKIP_TYPES = frozenset({EventType.FINDING, EventType.POLICY_RESULT})

#: Upper bound on characters scanned per extracted string (DoS protection).
MAX_SCAN_CHARS = 200_000


def iter_strings(obj: Any, path: str = "") -> Iterator[tuple[str, str]]:
    """Yield ``(json_path, text)`` for every string nested in ``obj``.

    Strings are truncated to :data:`MAX_SCAN_CHARS`; recursion is bounded by
    payload structure (already JSON-able, so no cycles).
    """
    if isinstance(obj, str):
        if obj:
            yield path, obj[:MAX_SCAN_CHARS]
    elif isinstance(obj, dict):
        for key, value in obj.items():
            yield from iter_strings(value, f"{path}.{key}" if path else str(key))
    elif isinstance(obj, list | tuple):
        for i, value in enumerate(obj):
            yield from iter_strings(value, f"{path}[{i}]")


class Finding(BaseModel):
    """One control observation, pointing at chained evidence."""

    model_config = ConfigDict(frozen=True)

    detector_id: str
    severity: Severity
    summary: str
    detail: dict[str, Any] = Field(default_factory=dict)
    # Stable key for idempotent re-runs: same observation → same key.
    dedupe_key: str
    session_id: str = "all"
    source_event_ids: list[str] = Field(default_factory=list)
    source_event_hashes: list[str] = Field(default_factory=list)
    framework_refs: list[str] = Field(default_factory=list)


class Detector(ABC):
    id: str

    @abstractmethod
    def inspect(self, events: list[AuditEvent], store: EvidenceStore) -> list[Finding]:
        """Inspect the (chain-ordered) events and return findings."""


@dataclass
class DetectionOutcome:
    events_scanned: int
    counts: dict[str, int]
    recorded: list[AuditEvent] = field(default_factory=list)
    summary_event: AuditEvent | None = None


class DetectorRunner:
    def __init__(self, detectors: list[Detector]) -> None:
        self.detectors = detectors

    def run(self, store: EvidenceStore, *, session_id: str | None = None) -> DetectionOutcome:
        already = {
            (e.payload.get("detector_id"), e.payload.get("dedupe_key"))
            for e in store.events(event_type=EventType.FINDING)
        }
        events = [
            e for e in store.events(session_id=session_id) if e.event_type not in _SKIP_TYPES
        ]

        counts: Counter[str] = Counter()
        recorded: list[AuditEvent] = []
        for detector in self.detectors:
            try:
                findings = detector.inspect(events, store)
            except Exception as exc:  # crash-safe: the failure IS a finding
                counts["detector_errors"] += 1
                findings = [
                    Finding(
                        detector_id=detector.id,
                        severity=Severity.MEDIUM,
                        summary=(
                            f"detector '{detector.id}' failed to run — "
                            "audit coverage is incomplete"
                        ),
                        detail={"error_type": type(exc).__name__, "error": str(exc)[:500]},
                        dedupe_key=f"detector-error:{type(exc).__name__}",
                    )
                ]
            for finding in findings:
                key = (finding.detector_id, finding.dedupe_key)
                if key in already:
                    counts["already_recorded"] += 1
                    continue
                already.add(key)
                counts[finding.severity.value] += 1
                recorded.append(
                    store.append(
                        session_id=finding.session_id,
                        app=_DETECT_APP,
                        event_type=EventType.FINDING,
                        payload=finding.model_dump(mode="json"),
                    )
                )

        summary = store.append(
            session_id=session_id or "all",
            app=_DETECT_APP,
            event_type=EventType.FINDING,
            payload={
                "op": "detector_run_summary",
                "events_scanned": len(events),
                "detectors": [d.id for d in self.detectors],
                "counts": dict(counts),
            },
        )
        return DetectionOutcome(
            events_scanned=len(events),
            counts=dict(counts),
            recorded=recorded,
            summary_event=summary,
        )
