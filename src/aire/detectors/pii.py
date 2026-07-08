"""PII detector backed by Microsoft Presidio (never homegrown regex).

Scans user input (newest request message), model output, and memory writes.

Security: findings record entity **types, scores, offsets, and paths** —
never the matched values. The evidence pointer identifies the source event;
duplicating raw PII into findings would only widen the exposure surface.

Requires the ``aire[pii]`` extra plus a spaCy model. Default model is
``en_core_web_sm`` (small, fast); use ``en_core_web_lg`` in production for
better recall — pass ``PresidioScanner(model="en_core_web_lg")``.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Protocol

from aire.core.events import AuditEvent, EventType
from aire.core.types import Severity
from aire.detectors.base import Detector, Finding, iter_strings
from aire.store import EvidenceStore

_FRAMEWORK_REFS = [
    "EU-AI-ACT:Art.10",
    "OWASP-LLM:LLM02",
    "NIST-AI-RMF:MEASURE-2.10",
    "ISO42001:A.5.4",
]


@dataclass(frozen=True)
class PIIMatch:
    entity_type: str
    score: float
    start: int
    end: int


class PIIScanner(Protocol):
    """Anything that can locate PII in text (Presidio in production)."""

    def scan(self, text: str) -> list[PIIMatch]: ...


class PresidioScanner:
    def __init__(
        self,
        *,
        model: str = "en_core_web_sm",
        language: str = "en",
        score_threshold: float = 0.4,
        entities: list[str] | None = None,
    ) -> None:
        try:
            from presidio_analyzer import AnalyzerEngine
            from presidio_analyzer.nlp_engine import NlpEngineProvider
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "PresidioScanner requires the 'pii' extra: pip install 'aire[pii]' "
                "and a spaCy model (python -m spacy download en_core_web_sm)"
            ) from exc

        nlp_engine = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": language, "model_name": model}],
            }
        ).create_engine()
        self._engine = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=[language])
        self._language = language
        self._threshold = score_threshold
        self._entities = entities

    def scan(self, text: str) -> list[PIIMatch]:
        results = self._engine.analyze(
            text=text, language=self._language, entities=self._entities
        )
        return [
            PIIMatch(entity_type=r.entity_type, score=r.score, start=r.start, end=r.end)
            for r in results
            if r.score >= self._threshold
        ]


class PIIDetector(Detector):
    id = "pii.content"

    def __init__(self, scanner: PIIScanner | None = None) -> None:
        self.scanner = scanner or PresidioScanner()

    def inspect(self, events: list[AuditEvent], store: EvidenceStore) -> list[Finding]:
        findings = []
        for event in events:
            texts = list(_texts_to_scan(event))
            if not texts:
                continue
            matches: list[dict] = []
            for path, text in texts:
                for m in self.scanner.scan(text):
                    matches.append(
                        {
                            "entity_type": m.entity_type,
                            "score": round(m.score, 3),
                            "start": m.start,
                            "end": m.end,
                            "path": path,
                        }
                    )
            if not matches:
                continue
            counts = Counter(m["entity_type"] for m in matches)
            summary_counts = ", ".join(f"{t}×{n}" for t, n in sorted(counts.items()))
            # PII persisted to memory is worse than PII in transit.
            severity = (
                Severity.HIGH if event.event_type == EventType.MEMORY_WRITE else Severity.MEDIUM
            )
            findings.append(
                Finding(
                    detector_id=self.id,
                    severity=severity,
                    summary=f"PII detected in {event.event_type.value} ({summary_counts})",
                    detail={"entity_counts": dict(counts), "matches": matches},
                    dedupe_key=event.event_id,
                    session_id=event.session_id,
                    source_event_ids=[event.event_id],
                    source_event_hashes=[event.hash],
                    framework_refs=_FRAMEWORK_REFS,
                )
            )
        return findings


def _texts_to_scan(event: AuditEvent):
    if event.event_type == EventType.LLM_REQUEST:
        messages = event.payload.get("messages") or []
        if messages:  # newest message only; history was scanned when new
            yield from iter_strings(messages[-1], path="messages[-1]")
    elif event.event_type == EventType.LLM_RESPONSE:
        yield from iter_strings(event.payload.get("content"), path="content")
    elif event.event_type == EventType.MEMORY_WRITE:
        yield from iter_strings(event.payload.get("channel_values"), path="channel_values")
        yield from iter_strings(event.payload.get("writes"), path="writes")
