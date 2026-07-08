"""Audit-log completeness detector.

An audit trail is only worth what its gaps admit. This detector turns three
kinds of gap into findings:

- a broken hash chain (tampering or corruption) — critical
- ``sensor.dropped`` events (the collector counted failures) — medium
- sessions with more llm.request than llm.response events (interactions the
  sensor started recording but never finished) — low
"""

from __future__ import annotations

from collections import Counter

from aire.core.events import AuditEvent, EventType
from aire.core.types import Severity
from aire.detectors.base import Detector, Finding
from aire.store import EvidenceStore

_FRAMEWORK_REFS = ["EU-AI-ACT:Art.12", "ISO42001:A.7.5", "NIST-AI-RMF:MEASURE-2.7"]


class CompletenessDetector(Detector):
    id = "audit_log.completeness"

    def inspect(self, events: list[AuditEvent], store: EvidenceStore) -> list[Finding]:
        findings: list[Finding] = []

        verification = store.verify()
        if not verification.ok:
            findings.append(
                Finding(
                    detector_id=self.id,
                    severity=Severity.CRITICAL,
                    summary=(
                        "evidence chain integrity FAILURE at "
                        f"seq={verification.first_bad_seq}: {verification.reason}"
                    ),
                    detail={
                        "first_bad_seq": verification.first_bad_seq,
                        "first_bad_event_id": verification.first_bad_event_id,
                        "intact_prefix": verification.checked,
                    },
                    dedupe_key=f"chain-break:{verification.first_bad_seq}",
                    framework_refs=_FRAMEWORK_REFS,
                )
            )

        requests: Counter[str] = Counter()
        responses: Counter[str] = Counter()
        for event in events:
            if event.event_type == EventType.SENSOR_DROPPED:
                count = event.payload.get("count", "?")
                findings.append(
                    Finding(
                        detector_id=self.id,
                        severity=Severity.MEDIUM,
                        summary=(
                            f"sensor dropped {count} event(s) before this point — "
                            "evidence for this session has gaps"
                        ),
                        detail={"dropped_count": count},
                        dedupe_key=event.event_id,
                        session_id=event.session_id,
                        source_event_ids=[event.event_id],
                        source_event_hashes=[event.hash],
                        framework_refs=_FRAMEWORK_REFS,
                    )
                )
            elif event.event_type == EventType.LLM_REQUEST:
                requests[event.session_id] += 1
            elif event.event_type == EventType.LLM_RESPONSE:
                responses[event.session_id] += 1

        for session_id, request_count in requests.items():
            response_count = responses.get(session_id, 0)
            if request_count > response_count:
                findings.append(
                    Finding(
                        detector_id=self.id,
                        severity=Severity.LOW,
                        summary=(
                            f"session has {request_count} llm.request but only "
                            f"{response_count} llm.response event(s) — "
                            "response capture may be incomplete"
                        ),
                        detail={"requests": request_count, "responses": response_count},
                        dedupe_key=f"unmatched:{session_id}:{request_count}:{response_count}",
                        session_id=session_id,
                        framework_refs=_FRAMEWORK_REFS,
                    )
                )
        return findings
