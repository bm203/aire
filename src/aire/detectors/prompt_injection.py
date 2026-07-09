"""Heuristic prompt-injection detector.

Scans the channels injections actually arrive through:

- ``llm.request`` — the *newest* message only (direct injection; earlier
  messages are resent history, already scanned when they were new)
- ``tool.result`` — indirect injection via data returned by tools (the
  AgentDojo threat model)
- ``retrieval.context`` — indirect injection via retrieved documents

Heuristics are pattern-based and deliberately transparent: every pattern has
an id and a weight, findings list exactly which patterns matched and where.
TP/FP rates are measured against AgentDojo in the evaluation phase — no
invented accuracy claims.

Security: patterns are precompiled, use no nested quantifiers (ReDoS-safe),
and inputs are size-bounded upstream (``iter_strings``).
"""

from __future__ import annotations

import re

from aire.core.events import AuditEvent, EventType
from aire.core.types import Severity
from aire.detectors.base import Detector, Finding, iter_strings
from aire.store import EvidenceStore

_FRAMEWORK_REFS = ["OWASP-LLM:LLM01", "EU-AI-ACT:Art.15", "NIST-AI-RMF:MEASURE-2.7"]

_EXCERPT_CHARS = 90

_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    (pattern_id, re.compile(regex, re.IGNORECASE), weight)
    for pattern_id, regex, weight in [
        (
            "ignore_instructions",
            r"ignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+"
            r"(?:instructions|directions|prompts?|rules)",
            1.0,
        ),
        ("disregard_instructions", r"disregard\s+(?:the\s+)?(?:previous|prior|above|system)", 1.0),
        (
            "new_instructions_marker",
            r"(?:important|attention|urgent)\W{0,3}\s*(?:new|updated)\s+instructions",
            0.9,
        ),
        (
            "system_prompt_probe",
            r"(?:reveal|show|print|repeat|output|display)\s+(?:your\s+)?"
            r"(?:system\s+prompt|initial\s+prompt|hidden\s+instructions)",
            1.0,
        ),
        ("role_override", r"you\s+are\s+now\s+(?:a|an|in)\b", 0.6),
        ("mode_override", r"(?:developer|god|jailbreak|dan)\s+mode", 0.9),
        ("do_anything_now", r"\bdo\s+anything\s+now\b", 0.9),
        ("fake_control_tokens", r"</?(?:system|assistant)>|\[/?(?:INST|SYSTEM)\]", 0.8),
        # Fake authoritative context blocks injected into tool/retrieved data.
        ("fake_framing_tag", r"</?(?:INFORMATION|INSTRUCTIONS?|IMPORTANT|CONTEXT)>", 0.7),
        # "Before you (can) solve/answer the task … do the following first" —
        # the injected-precondition preamble common to indirect-injection attacks.
        (
            "injected_precondition",
            r"before you\s+(?:can |could |may )?(?:solve|complete|answer|continue|"
            r"proceed|finish|respond)\b[^.]{0,80}?"
            r"(?:do|complete|perform|follow|execute)\s+the\s+following",
            0.8,
        ),
        # Content framed as an authoritative out-of-band message to the model.
        (
            "authoritative_message_framing",
            r"(?:important|urgent)\s+message\s+(?:from|for)\s+(?:me|us|the\s+\w{1,20})"
            r"[,\s][^.]{0,40}?to you",
            0.6,
        ),
        ("exfil_markdown_image", r"!\[[^\]\n]{0,64}\]\(https?://", 0.9),
        (
            "exfil_send_to_url",
            r"(?:send|post|forward|upload)\s+(?:this|it|them|the\s+\w{1,20})\s+to\s+https?://",
            1.0,
        ),
        (
            "pretend_no_rules",
            r"pretend\s+(?:that\s+)?(?:you\s+)?(?:have|has)\s+no\s+"
            r"(?:rules|restrictions|guidelines)",
            0.9,
        ),
    ]
]


class PromptInjectionDetector(Detector):
    id = "prompt_injection.heuristic"

    def __init__(self, threshold: float = 0.8) -> None:
        self.threshold = threshold

    def inspect(self, events: list[AuditEvent], store: EvidenceStore) -> list[Finding]:
        findings = []
        for event in events:
            texts = list(_texts_to_scan(event))
            if not texts:
                continue
            matches, score = [], 0.0
            for path, text in texts:
                for pattern_id, pattern, weight in _PATTERNS:
                    m = pattern.search(text)
                    if m:
                        score += weight
                        lo = max(0, m.start() - 20)
                        matches.append(
                            {
                                "pattern": pattern_id,
                                "path": path,
                                "excerpt": text[lo : m.start() + _EXCERPT_CHARS],
                            }
                        )
            if matches and score >= self.threshold:
                findings.append(
                    Finding(
                        detector_id=self.id,
                        severity=Severity.HIGH,
                        summary=(
                            f"possible prompt injection in {event.event_type.value} "
                            f"(score {score:.1f}, patterns: "
                            f"{', '.join(sorted({m['pattern'] for m in matches}))})"
                        ),
                        detail={"score": score, "threshold": self.threshold, "matches": matches},
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
        if messages:
            yield from iter_strings(messages[-1], path="messages[-1]")
    elif event.event_type == EventType.TOOL_RESULT:
        yield from iter_strings(event.payload.get("content"), path="content")
    elif event.event_type == EventType.RETRIEVAL_CONTEXT:
        yield from iter_strings(event.payload, path="payload")
