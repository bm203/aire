"""Fail-open recording core shared by all collectors.

The cardinal rule: **the sensor can never break the host application.**
Payload construction and store writes happen inside a guard; any failure is
swallowed and counted. The dropped count is flushed as a ``sensor.dropped``
event on the next successful write, so gaps in the evidence are themselves
evidence (the completeness detector turns them into findings).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from aire.collectors.context import current_session_id, current_trace_id
from aire.core.events import EventType
from aire.store import EvidenceStore

UNATTRIBUTED = "unattributed"


def jsonable(obj: Any) -> Any:
    """Best-effort conversion to JSON-serializable data (never raises)."""
    try:
        if obj is None or isinstance(obj, str | int | float | bool):
            return obj
        if hasattr(obj, "model_dump"):  # pydantic (Anthropic SDK objects)
            return jsonable(obj.model_dump())
        if isinstance(obj, dict):
            return {str(k): jsonable(v) for k, v in obj.items()}
        if isinstance(obj, list | tuple | set):
            return [jsonable(v) for v in obj]
        return str(obj)
    except Exception:
        return "<unserializable>"


class Sensor:
    """Records events to an :class:`EvidenceStore`, guaranteed non-raising."""

    def __init__(self, *, store: EvidenceStore, app: str) -> None:
        self.store = store
        self.app = app
        self.dropped = 0

    def record(
        self,
        event_type: EventType,
        payload_fn: Callable[[], dict[str, Any]],
        *,
        session_id: str | None = None,
    ) -> None:
        """Build and store an event; on any failure, count a drop and move on.

        ``payload_fn`` is called inside the guard so a crashing serializer
        can't reach the host app either.
        """
        try:
            sid = session_id or current_session_id() or UNATTRIBUTED
            payload = payload_fn()
            if self.dropped:
                pending, self.dropped = self.dropped, 0
                try:
                    self.store.append(
                        session_id=sid,
                        app=self.app,
                        event_type=EventType.SENSOR_DROPPED,
                        payload={"count": pending},
                    )
                except Exception:
                    self.dropped += pending  # flush failed; keep counting
            self.store.append(
                session_id=sid,
                trace_id=current_trace_id(),
                app=self.app,
                event_type=event_type,
                payload=payload,
            )
        except Exception:
            self.dropped += 1
