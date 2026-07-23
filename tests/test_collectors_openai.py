"""OpenAI/Azure-OpenAI collector tests against a duck-typed fake client.

The collector never imports the openai package, so these tests don't either
— they exercise the exact attribute surface the collector reads.
"""

from dataclasses import dataclass, field
from typing import Any

import pytest

from aire.collectors import session
from aire.collectors.openai_sdk import instrument
from aire.core.events import EventType
from aire.store import EvidenceStore


@dataclass
class FakeUsage:
    prompt_tokens: int = 10
    completion_tokens: int = 20


@dataclass
class FakeFunction:
    name: str
    arguments: str


@dataclass
class FakeToolCall:
    id: str
    function: FakeFunction


@dataclass
class FakeMessage:
    content: str | None = "hi there"
    tool_calls: list | None = None


@dataclass
class FakeChoice:
    message: FakeMessage = field(default_factory=FakeMessage)
    finish_reason: str = "stop"


@dataclass
class FakeResponse:
    id: str = "chatcmpl_123"
    model: str = "gpt-4o"
    usage: FakeUsage = field(default_factory=FakeUsage)
    choices: list = field(default_factory=lambda: [FakeChoice()])


class FakeCompletions:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.calls: list[dict[str, Any]] = []

    def create(self, **kwargs: Any) -> FakeResponse:
        self.calls.append(kwargs)
        return self.response


class FakeChat:
    def __init__(self, response: FakeResponse) -> None:
        self.completions = FakeCompletions(response)


class FakeClient:
    def __init__(self, response: FakeResponse | None = None) -> None:
        self.chat = FakeChat(response or FakeResponse())
        self.api_key = "sk-fake"


@pytest.fixture
def store(tmp_path):
    s = EvidenceStore(tmp_path / "evidence.db")
    yield s
    s.close()


REQUEST_KWARGS = dict(
    model="gpt-4o",
    max_tokens=16000,
    tools=[{"type": "function", "function": {"name": "lookup_order", "parameters": {}}}],
    messages=[{"role": "user", "content": "where is order 1234?"}],
)


def events_by_type(store):
    grouped: dict[EventType, list] = {}
    for e in store.events():
        grouped.setdefault(e.event_type, []).append(e)
    return grouped


class TestCreate:
    def test_response_is_returned_unchanged(self, store):
        fake = FakeClient()
        client = instrument(fake, store=store, app="t")
        response = client.chat.completions.create(**REQUEST_KWARGS)
        assert response is fake.chat.completions.response
        assert fake.chat.completions.calls[0]["model"] == "gpt-4o"

    def test_request_and_response_events_recorded(self, store):
        client = instrument(FakeClient(), store=store, app="t")
        with session("sess-9", trace_id="tr-1"):
            client.chat.completions.create(**REQUEST_KWARGS)
        by_type = events_by_type(store)

        req = by_type[EventType.LLM_REQUEST][0]
        assert req.session_id == "sess-9"
        assert req.trace_id == "tr-1"
        assert req.app == "t"
        assert req.payload["gen_ai.system"] == "openai"
        assert req.payload["gen_ai.request.model"] == "gpt-4o"
        assert req.payload["tools_offered"] == ["lookup_order"]
        assert req.payload["messages"][0]["content"] == "where is order 1234?"

        resp = by_type[EventType.LLM_RESPONSE][0]
        assert resp.payload["gen_ai.usage.input_tokens"] == 10
        assert resp.payload["gen_ai.usage.output_tokens"] == 20
        assert resp.payload["gen_ai.response.finish_reasons"] == ["stop"]
        assert resp.payload["content"] == "hi there"
        assert resp.payload["latency_ms"] >= 0

    def test_azure_system_label_is_recorded(self, store):
        client = instrument(FakeClient(), store=store, app="t", system="azure.ai.openai")
        client.chat.completions.create(**REQUEST_KWARGS)
        req = events_by_type(store)[EventType.LLM_REQUEST][0]
        assert req.payload["gen_ai.system"] == "azure.ai.openai"

    def test_tool_calls_become_tool_call_events(self, store):
        response = FakeResponse(
            choices=[
                FakeChoice(
                    finish_reason="tool_calls",
                    message=FakeMessage(
                        content=None,
                        tool_calls=[
                            FakeToolCall(
                                id="call_1",
                                function=FakeFunction(
                                    name="lookup_order", arguments='{"order_id": "1234"}'
                                ),
                            )
                        ],
                    ),
                )
            ]
        )
        client = instrument(FakeClient(response), store=store, app="t")
        client.chat.completions.create(**REQUEST_KWARGS)
        calls = events_by_type(store)[EventType.TOOL_CALL]
        assert len(calls) == 1
        assert calls[0].payload["gen_ai.tool.name"] == "lookup_order"
        assert calls[0].payload["tool_use_id"] == "call_1"
        assert calls[0].payload["input"] == {"order_id": "1234"}

    def test_malformed_tool_arguments_keep_raw_string(self, store):
        response = FakeResponse(
            choices=[
                FakeChoice(
                    message=FakeMessage(
                        tool_calls=[
                            FakeToolCall(
                                id="call_1", function=FakeFunction(name="f", arguments="{not json")
                            )
                        ]
                    )
                )
            ]
        )
        client = instrument(FakeClient(response), store=store, app="t")
        client.chat.completions.create(**REQUEST_KWARGS)
        calls = events_by_type(store)[EventType.TOOL_CALL]
        assert calls[0].payload["input"] == "{not json"

    def test_trailing_tool_messages_recorded(self, store):
        client = instrument(FakeClient(), store=store, app="t")
        kwargs = dict(REQUEST_KWARGS)
        kwargs["messages"] = [
            {"role": "user", "content": "hi"},
            {"role": "assistant", "content": None, "tool_calls": []},
            {"role": "tool", "tool_call_id": "call_1", "content": "shipped"},
        ]
        client.chat.completions.create(**kwargs)
        results = events_by_type(store)[EventType.TOOL_RESULT]
        assert len(results) == 1
        assert results[0].payload == {"tool_use_id": "call_1", "content": "shipped"}

    def test_unattributed_without_session_context(self, store):
        client = instrument(FakeClient(), store=store, app="t")
        client.chat.completions.create(**REQUEST_KWARGS)
        assert all(e.session_id == "unattributed" for e in store.events())

    def test_non_chat_attributes_pass_through(self, store):
        client = instrument(FakeClient(), store=store, app="t")
        assert client.api_key == "sk-fake"


class TestStreaming:
    def test_streaming_records_request_only_and_returns_stream_unchanged(self, store):
        fake = FakeClient()
        marker = object()
        fake.chat.completions.create = lambda **kw: marker  # simulate a Stream object
        client = instrument(fake, store=store, app="t")

        kwargs = dict(REQUEST_KWARGS)
        kwargs["stream"] = True
        result = client.chat.completions.create(**kwargs)

        assert result is marker  # never touched, never consumed
        by_type = events_by_type(store)
        assert len(by_type[EventType.LLM_REQUEST]) == 1
        assert EventType.LLM_RESPONSE not in by_type


class TestFailOpen:
    class ExplodingStore:
        path = "nowhere"

        def append(self, **kwargs):
            raise RuntimeError("disk on fire")

    def test_store_failure_never_reaches_the_app(self, store):
        fake = FakeClient()
        client = instrument(fake, store=self.ExplodingStore(), app="t")
        response = client.chat.completions.create(**REQUEST_KWARGS)  # must not raise
        assert response is fake.chat.completions.response

    def test_dropped_events_flush_when_store_recovers(self, store):
        client = instrument(FakeClient(), store=store, app="t")
        sensor = client.chat.completions._sensor

        real_append = store.append

        def broken_append(**kwargs):
            raise RuntimeError("db locked")

        store.append = broken_append
        client.chat.completions.create(**REQUEST_KWARGS)  # request+response both dropped
        assert sensor.dropped == 2

        store.append = real_append
        client.chat.completions.create(**REQUEST_KWARGS)
        dropped_events = events_by_type(store)[EventType.SENSOR_DROPPED]
        assert dropped_events[0].payload["count"] == 2
        assert sensor.dropped == 0

    def test_payload_serializer_crash_is_contained(self, store):
        class EvilResponse:
            id = "chatcmpl_evil"
            model = "gpt-4o"

            @property
            def usage(self):
                raise RuntimeError("boom")

            choices: list = []

        fake = FakeClient()
        fake.chat.completions.response = EvilResponse()
        client = instrument(fake, store=store, app="t")
        response = client.chat.completions.create(**REQUEST_KWARGS)  # must not raise
        assert response is fake.chat.completions.response
