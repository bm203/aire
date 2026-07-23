"""Observe-only collector for the OpenAI SDK — also covers Azure OpenAI, since
``openai.AzureOpenAI`` exposes the same ``chat.completions.create`` interface.

Usage::

    import openai
    from aire.collectors.openai_sdk import instrument
    from aire.store import EvidenceStore

    store = EvidenceStore("evidence.db")
    client = instrument(openai.OpenAI(), store=store, app="my-app")
    # Azure: client = instrument(openai.AzureOpenAI(...), store=store,
    #                            app="my-app", system="azure.ai.openai")
    # use `client` exactly like a normal OpenAI/AzureOpenAI client

The wrapper records ``llm.request`` / ``llm.response`` events, ``tool.call``
events for tool calls in responses, and ``tool.result`` events for the
``role: "tool"`` messages the app sends back. It never transforms, blocks, or
redacts anything, and it is fail-open: recording errors are swallowed and
counted (see :class:`aire.collectors.base.Sensor`).

This module is duck-typed — it does not import the ``openai`` package, so the
core install stays lean and unit tests run against fakes.

Scope: the Chat Completions API (``client.chat.completions.create``) — the
surface both OpenAI and Azure OpenAI share, and what most existing agent
frameworks target. Streaming (``stream=True``) is only partially covered:
the request is recorded, but the streamed response's content and any tool
calls are not, since consuming the app's stream to capture them would risk
the one thing this sensor must never do — interfere with the host. Extend
this the way ``anthropic_sdk.py``'s ``_InstrumentedStream`` does, if needed.
"""

from __future__ import annotations

import json
import time
from typing import Any

from aire.collectors.base import Sensor, jsonable
from aire.core.events import EventType
from aire.store import EvidenceStore


def instrument(
    client: Any, *, store: EvidenceStore, app: str, system: str = "openai"
) -> Any:
    """Wrap an ``openai.OpenAI`` / ``openai.AzureOpenAI`` (or compatible) client.

    ``system`` is recorded as ``gen_ai.system`` on every event; pass e.g.
    ``system="azure.ai.openai"`` when instrumenting an Azure client so the
    evidence reflects the actual backend.
    """
    return _InstrumentedClient(client, Sensor(store=store, app=app), system)


class _InstrumentedClient:
    def __init__(self, inner: Any, sensor: Sensor, system: str) -> None:
        self._inner = inner
        self._sensor = sensor
        self.chat = _InstrumentedChat(inner.chat, sensor, system)

    def __getattr__(self, name: str) -> Any:  # everything else passes through
        return getattr(self._inner, name)


class _InstrumentedChat:
    def __init__(self, inner: Any, sensor: Sensor, system: str) -> None:
        self._inner = inner
        self.completions = _InstrumentedCompletions(inner.completions, sensor, system)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


class _InstrumentedCompletions:
    def __init__(self, inner: Any, sensor: Sensor, system: str) -> None:
        self._inner = inner
        self._sensor = sensor
        self._system = system

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def create(self, **kwargs: Any) -> Any:
        self._record_request(kwargs)
        start = time.monotonic()
        response = self._inner.create(**kwargs)  # host errors propagate untouched
        if not kwargs.get("stream"):
            self._record_response(response, latency_ms=(time.monotonic() - start) * 1000)
        return response

    # -- recording ---------------------------------------------------------

    def _record_request(self, kwargs: dict[str, Any]) -> None:
        self._sensor.record(
            EventType.LLM_REQUEST, lambda: _request_payload(kwargs, self._system)
        )
        # trailing role="tool" messages are results the app appended since the
        # last turn; earlier messages are resent history recorded on prior turns.
        messages = kwargs.get("messages") or []
        trailing: list[dict[str, Any]] = []
        for msg in reversed(messages):
            if isinstance(msg, dict) and msg.get("role") == "tool":
                trailing.append(msg)
            else:
                break
        for msg in reversed(trailing):  # restore chronological order
            self._sensor.record(
                EventType.TOOL_RESULT,
                lambda m=msg: {
                    "tool_use_id": m.get("tool_call_id"),
                    "content": jsonable(m.get("content")),
                },
            )

    def _record_response(self, response: Any, *, latency_ms: float) -> None:
        self._sensor.record(
            EventType.LLM_RESPONSE,
            lambda: _response_payload(response, latency_ms, self._system),
        )
        choice = (getattr(response, "choices", None) or [None])[0]
        message = getattr(choice, "message", None)
        for tc in getattr(message, "tool_calls", None) or []:
            self._sensor.record(
                EventType.TOOL_CALL,
                lambda t=tc: {
                    "gen_ai.tool.name": getattr(getattr(t, "function", None), "name", None),
                    "tool_use_id": getattr(t, "id", None),
                    "input": _parse_tool_arguments(
                        getattr(getattr(t, "function", None), "arguments", None)
                    ),
                },
            )


def _parse_tool_arguments(arguments: str | None) -> Any:
    """Tool arguments arrive as a JSON string; keep the raw string on parse
    failure rather than lose evidence."""
    if arguments is None:
        return None
    try:
        return json.loads(arguments)
    except (TypeError, ValueError):
        return arguments


def _request_payload(kwargs: dict[str, Any], system: str) -> dict[str, Any]:
    tools = kwargs.get("tools") or []
    return {
        "gen_ai.system": system,
        "gen_ai.operation.name": "chat",
        "gen_ai.request.model": kwargs.get("model"),
        "gen_ai.request.max_tokens": kwargs.get("max_tokens"),
        "messages": jsonable(kwargs.get("messages")),
        "tools_offered": [
            (t.get("function") or {}).get("name") if isinstance(t, dict) else str(t)
            for t in tools
        ],
    }


def _response_payload(response: Any, latency_ms: float, system: str) -> dict[str, Any]:
    usage = getattr(response, "usage", None)
    choice = (getattr(response, "choices", None) or [None])[0]
    message = getattr(choice, "message", None)
    return {
        "gen_ai.system": system,
        "gen_ai.response.id": getattr(response, "id", None),
        "gen_ai.response.model": getattr(response, "model", None),
        "gen_ai.response.finish_reasons": [getattr(choice, "finish_reason", None)],
        "gen_ai.usage.input_tokens": getattr(usage, "prompt_tokens", None),
        "gen_ai.usage.output_tokens": getattr(usage, "completion_tokens", None),
        "content": jsonable(getattr(message, "content", None)),
        "latency_ms": round(latency_ms, 3),
    }
