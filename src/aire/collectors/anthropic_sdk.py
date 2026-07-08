"""Observe-only collector for the Anthropic SDK.

Usage::

    import anthropic
    from aire.collectors.anthropic_sdk import instrument
    from aire.store import EvidenceStore

    store = EvidenceStore("evidence.db")
    client = instrument(anthropic.Anthropic(), store=store, app="my-app")
    # use `client` exactly like a normal Anthropic client

The wrapper records ``llm.request`` / ``llm.response`` events, ``tool.call``
events for tool_use blocks in responses, and ``tool.result`` events for
tool_result blocks the app sends back. It never transforms, blocks, or
redacts anything, and it is fail-open: recording errors are swallowed and
counted (see :class:`aire.collectors.base.Sensor`).

This module is duck-typed — it does not import the ``anthropic`` package, so
the core install stays lean and unit tests run against fakes.
"""

from __future__ import annotations

import time
from typing import Any

from aire.collectors.base import Sensor, jsonable
from aire.core.events import EventType
from aire.store import EvidenceStore


def instrument(client: Any, *, store: EvidenceStore, app: str) -> Any:
    """Wrap an ``anthropic.Anthropic`` (or compatible) client for observation."""
    return _InstrumentedClient(client, Sensor(store=store, app=app))


class _InstrumentedClient:
    def __init__(self, inner: Any, sensor: Sensor) -> None:
        self._inner = inner
        self._sensor = sensor
        self.messages = _InstrumentedMessages(inner.messages, sensor)

    def __getattr__(self, name: str) -> Any:  # everything else passes through
        return getattr(self._inner, name)


class _InstrumentedMessages:
    def __init__(self, inner: Any, sensor: Sensor) -> None:
        self._inner = inner
        self._sensor = sensor

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def create(self, **kwargs: Any) -> Any:
        self._record_request(kwargs)
        start = time.monotonic()
        response = self._inner.create(**kwargs)  # host errors propagate untouched
        self._record_response(response, latency_ms=(time.monotonic() - start) * 1000)
        return response

    def stream(self, **kwargs: Any) -> Any:
        self._record_request(kwargs)
        start = time.monotonic()
        return _InstrumentedStream(self._inner.stream(**kwargs), self, start)

    # -- recording ---------------------------------------------------------

    def _record_request(self, kwargs: dict[str, Any]) -> None:
        self._sensor.record(EventType.LLM_REQUEST, lambda: _request_payload(kwargs))
        # tool_result blocks the app sends back live in the newest message;
        # earlier messages are resent history and were recorded on prior turns.
        messages = kwargs.get("messages") or []
        last = messages[-1] if messages else None
        content = last.get("content") if isinstance(last, dict) else None
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    self._sensor.record(
                        EventType.TOOL_RESULT,
                        lambda b=block: {
                            "tool_use_id": b.get("tool_use_id"),
                            "content": jsonable(b.get("content")),
                            "is_error": bool(b.get("is_error", False)),
                        },
                    )

    def _record_response(self, response: Any, *, latency_ms: float) -> None:
        self._sensor.record(
            EventType.LLM_RESPONSE, lambda: _response_payload(response, latency_ms)
        )
        for block in getattr(response, "content", None) or []:
            if getattr(block, "type", None) == "tool_use":
                self._sensor.record(
                    EventType.TOOL_CALL,
                    lambda b=block: {
                        "gen_ai.tool.name": getattr(b, "name", None),
                        "tool_use_id": getattr(b, "id", None),
                        "input": jsonable(getattr(b, "input", None)),
                    },
                )


class _InstrumentedStream:
    """Wraps the SDK's MessageStream context manager.

    Yields the raw stream untouched; on clean exit, records the final message
    (cached by the SDK once the stream is consumed). Fail-open throughout.
    """

    def __init__(self, inner_cm: Any, messages: _InstrumentedMessages, start: float) -> None:
        self._cm = inner_cm
        self._messages = messages
        self._start = start
        self._stream: Any = None

    def __enter__(self) -> Any:
        self._stream = self._cm.__enter__()
        return self._stream

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> Any:
        if exc_type is None and self._stream is not None:
            try:
                final = self._stream.get_final_message()
            except Exception:
                final = None
            if final is not None:
                self._messages._record_response(
                    final, latency_ms=(time.monotonic() - self._start) * 1000
                )
        return self._cm.__exit__(exc_type, exc, tb)


def _request_payload(kwargs: dict[str, Any]) -> dict[str, Any]:
    tools = kwargs.get("tools") or []
    return {
        "gen_ai.system": "anthropic",
        "gen_ai.operation.name": "chat",
        "gen_ai.request.model": kwargs.get("model"),
        "gen_ai.request.max_tokens": kwargs.get("max_tokens"),
        "system": jsonable(kwargs.get("system")),
        "messages": jsonable(kwargs.get("messages")),
        "tools_offered": [
            t.get("name") if isinstance(t, dict) else getattr(t, "name", str(t)) for t in tools
        ],
    }


def _response_payload(response: Any, latency_ms: float) -> dict[str, Any]:
    usage = getattr(response, "usage", None)
    return {
        "gen_ai.system": "anthropic",
        "gen_ai.response.id": getattr(response, "id", None),
        "gen_ai.response.model": getattr(response, "model", None),
        "gen_ai.response.finish_reasons": [getattr(response, "stop_reason", None)],
        "gen_ai.usage.input_tokens": getattr(usage, "input_tokens", None),
        "gen_ai.usage.output_tokens": getattr(usage, "output_tokens", None),
        "content": jsonable(getattr(response, "content", None)),
        "latency_ms": round(latency_ms, 3),
    }
