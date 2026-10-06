"""Fail-open recording core shared by all collectors.

The cardinal rule: **the sensor can never break the host application.**
Payload construction happens inside a guard; any failure is swallowed and
counted. The dropped count is flushed as a ``sensor.dropped`` event on the next
successful write, so gaps in the evidence are themselves evidence (the
completeness detector turns them into findings).

By default (``background=True``) the store write happens on a background
writer thread (``aire.collectors._writer``): the host thread only builds the
payload and puts it on a bounded queue, so it never waits on the database. A
full queue is a counted drop. ``background=False`` writes synchronously on the
calling thread, which is what offline importers and some tests want.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from aire.collectors import _writer
from aire.collectors.context import current_session_id, current_trace_id
from aire.core.events import EventType, _utcnow_iso
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

    def __init__(
        self,
        *,
        store: EvidenceStore,
        app: str,
        background: bool = True,
        max_queue: int = _writer.DEFAULT_MAX_QUEUE,
    ) -> None:
        self.store = store
        self.app = app
        self.dropped = 0
        self._writer: _writer.BackgroundWriter | None = None
        # Background writing needs a real, writable store (the writer opens its
        # own connection to the same file). Anything else, including duck-typed
        # test doubles, records synchronously. Construction must never raise.
        if background and isinstance(store, EvidenceStore) and not store.read_only:
            try:
                self._writer = _writer.get_writer(store.path, max_queue)
                _writer.register_drop_reporter(self)
            except Exception:
                self._writer = None
        self._last_session = UNATTRIBUTED

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
            self._last_session = sid
            payload = payload_fn()
            event = {
                "session_id": sid,
                "trace_id": current_trace_id(),
                "app": self.app,
                "event_type": event_type,
                "payload": payload,
                "ts": _utcnow_iso(),  # when it happened, not when it was written
            }
            if self._writer is not None:
                self._submit(event)
                return
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
            self.store.append(**event)
        except Exception:
            self.dropped += 1

    def _submit(self, event: dict[str, Any]) -> None:
        """Hand an event to the background writer without ever blocking."""
        if self.dropped:
            notice = {**event, "trace_id": None, "event_type": EventType.SENSOR_DROPPED,
                      "payload": {"count": self.dropped}}
            if self._writer.submit(notice):
                self.dropped = 0
        if not self._writer.submit(event):
            self.dropped += 1

    def report_drops(self) -> None:
        """Turn a pending drop count into a ``sensor.dropped`` event now.

        Drops are normally reported with the next event; without this, a burst
        of drops at the end of a run would live only in memory and vanish.
        Called by ``flush`` and at interpreter shutdown.
        """
        if self._writer is None or not self.dropped:
            return
        notice = {"session_id": self._last_session, "trace_id": None, "app": self.app,
                  "event_type": EventType.SENSOR_DROPPED, "payload": {"count": self.dropped},
                  "ts": _utcnow_iso()}
        if self._writer.submit(notice):
            self.dropped = 0

    def flush(self, timeout: float = _writer.READ_FLUSH_SECONDS) -> bool:
        """Report pending drops, then wait for queued events to be written.

        A no-op in synchronous mode.
        """
        if self._writer is None:
            return True
        self.report_drops()
        if self.dropped and self._writer.flush(timeout):
            self.report_drops()  # the queue was full a moment ago; it has room now
        return self._writer.flush(timeout)
