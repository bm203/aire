"""Policy engine: evaluate compiled policies over stored evidence.

Runs out-of-band over the evidence store (never inline in the host app's
request path). Results are themselves appended to the hash chain as
``policy.result`` events, so the audit trail covers not just what the AI did
but what the policy evaluation concluded — and when.

Recording strategy: fail/warn/error results are recorded per event with an
evidence pointer (source event id + hash). Pass results are aggregated into
a single per-run summary event — coverage proof without drowning the log.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from aire.core.events import AuditEvent, EventType
from aire.policy.backend import (
    CompiledExpression,
    ExpressionCompileError,
    ExpressionEvalError,
    PolicyBackend,
)
from aire.policy.cel_backend import CELBackend
from aire.policy.models import Policy, PolicyResult, Verdict
from aire.store import EvidenceStore

_ENGINE_APP = "aire.policy"
_SKIP_TYPES = frozenset({EventType.POLICY_RESULT, EventType.FINDING})


class PolicyCompileError(Exception):
    pass


@dataclass
class RunOutcome:
    events_evaluated: int
    counts: dict[str, int]
    recorded: list[AuditEvent] = field(default_factory=list)
    summary_event: AuditEvent | None = None


class PolicyEngine:
    def __init__(self, policies: list[Policy], backend: PolicyBackend | None = None) -> None:
        self.backend = backend or CELBackend()
        self._compiled: list[tuple[Policy, CompiledExpression]] = []
        for policy in policies:
            try:
                expression = self.backend.compile(policy.violation)
            except ExpressionCompileError as exc:
                raise PolicyCompileError(f"policy {policy.id}: {exc}") from exc
            self._compiled.append((policy, expression))

    @property
    def policies(self) -> list[Policy]:
        return [p for p, _ in self._compiled]

    def evaluate_event(self, event: AuditEvent) -> list[PolicyResult]:
        """Evaluate all applicable policies against one event."""
        return [
            self._evaluate_one(policy, expression, event)
            for policy, expression in self._compiled
            if event.event_type in policy.applies_to
        ]

    def run(self, store: EvidenceStore, *, session_id: str | None = None) -> RunOutcome:
        """Evaluate every stored event; append fail/warn/error results + a summary.

        Idempotent per (policy, event): results already on the chain are not
        recorded (or counted) again, so re-running never duplicates evidence.
        """
        already = {
            (e.payload.get("policy_id"), e.payload.get("source_event_id"))
            for e in store.events(event_type=EventType.POLICY_RESULT)
        }
        # Materialize before appending results, or we'd iterate our own output.
        events = [
            e
            for e in store.events(session_id=session_id)
            if e.event_type not in _SKIP_TYPES
        ]

        counts: Counter[str] = Counter()
        recorded: list[AuditEvent] = []
        for event in events:
            for policy, expression in self._compiled:
                if event.event_type not in policy.applies_to:
                    continue
                if (policy.id, event.event_id) in already:
                    counts["already_recorded"] += 1
                    continue
                result = self._evaluate_one(policy, expression, event)
                counts[result.verdict.value] += 1
                if result.verdict is not Verdict.PASS:
                    recorded.append(
                        store.append(
                            session_id=result.source_session_id,
                            app=_ENGINE_APP,
                            event_type=EventType.POLICY_RESULT,
                            payload=result.model_dump(mode="json"),
                        )
                    )

        summary = store.append(
            session_id=session_id or "all",
            app=_ENGINE_APP,
            event_type=EventType.POLICY_RESULT,
            payload={
                "op": "run_summary",
                "events_evaluated": len(events),
                "policies": [p.id for p, _ in self._compiled],
                "backend": self.backend.name,
                "counts": dict(counts),
            },
        )
        return RunOutcome(
            events_evaluated=len(events),
            counts=dict(counts),
            recorded=recorded,
            summary_event=summary,
        )

    @staticmethod
    def _variables(event: AuditEvent, policy: Policy) -> dict:
        return {
            "event": {
                "event_type": event.event_type.value,
                "session_id": event.session_id,
                "trace_id": event.trace_id,
                "app": event.app,
                "ts": event.ts,
            },
            "payload": event.payload,
            "params": policy.params,
        }

    def _evaluate_one(
        self, policy: Policy, expression: CompiledExpression, event: AuditEvent
    ) -> PolicyResult:
        common = dict(
            policy_id=policy.id,
            severity=policy.severity,
            framework_refs=policy.framework_refs,
            source_event_id=event.event_id,
            source_event_hash=event.hash,
            source_session_id=event.session_id,
        )
        try:
            violated = expression.evaluate(self._variables(event, policy))
        except ExpressionEvalError as exc:
            return PolicyResult(
                verdict=Verdict.ERROR,
                explanation=f"{policy.description} — NOT EVALUATED against this event: {exc}",
                **common,
            )
        if violated:
            return PolicyResult(
                verdict=policy.verdict_on_violation,
                explanation=f"{policy.description} — violation condition matched.",
                **common,
            )
        return PolicyResult(
            verdict=Verdict.PASS,
            explanation=f"{policy.description} — no violation.",
            **common,
        )
