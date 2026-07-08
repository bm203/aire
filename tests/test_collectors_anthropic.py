"""Anthropic collector tests against a duck-typed fake client.

The collector never imports the anthropic package, so these tests don't
either — they exercise the exact attribute surface the collector reads.
"""

from dataclasses import dataclass, field
from typing import Any

import pytest

from aire.collectors import session
from aire.collectors.anthropic_sdk import instrument
from aire.core.events import EventType
from aire.store import EvidenceStore


@dataclass
class FakeUsage:
    input_tokens: int = 10
    output_tokens: int = 20


@dataclass
class FakeBlock:
    type: str
    text: str | None = None
    name: str | None = None
    id: str | None = None
    input: dict | None = None

    def model_dump(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v is not None}


@dataclass
class FakeResponse:
    id: str = "msg_123"
    model: str = "claude-opus-4-8"
    stop_reason: str = "end_turn"
    usage: FakeUsage = field(default_factory=FakeUsage)
    content: list = field(default_factory=lambda: [FakeBlock(type="text", text="hi there")])


class FakeMessages:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.calls: list[dict[str, Any]] = []

    def create(self, **kwargs: Any) -> FakeResponse:
        self.calls.append(kwargs)
        return self.response


class FakeClient:
    def __init__(self, response: FakeResponse | None = None) -> None:
        self.messages = FakeMessages(response or FakeResponse())
        self.api_key = "sk-fake"


@pytest.fixture
def store(tmp_path):
    s = EvidenceStore(tmp_path / "evidence.db")
    yield s
    s.close()


REQUEST_KWARGS = dict(
    model="claude-opus-4-8",
    max_tokens=16000,
    system="be helpful",
    tools=[{"name": "lookup_order", "input_schema": {}}],
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
        response = client.messages.create(**REQUEST_KWARGS)
        assert response is fake.messages.response
        assert fake.messages.calls[0]["model"] == "claude-opus-4-8"

    def test_request_and_response_events_recorded(self, store):
        client = instrument(FakeClient(), store=store, app="t")
        with session("sess-9", trace_id="tr-1"):
            client.messages.create(**REQUEST_KWARGS)
        by_type = events_by_type(store)

        req = by_type[EventType.LLM_REQUEST][0]
        assert req.session_id == "sess-9"
        assert req.trace_id == "tr-1"
        assert req.app == "t"
        assert req.payload["gen_ai.request.model"] == "claude-opus-4-8"
        assert req.payload["tools_offered"] == ["lookup_order"]
        assert req.payload["messages"][0]["content"] == "where is order 1234?"

        resp = by_type[EventType.LLM_RESPONSE][0]
        assert resp.payload["gen_ai.usage.input_tokens"] == 10
        assert resp.payload["gen_ai.usage.output_tokens"] == 20
        assert resp.payload["gen_ai.response.finish_reasons"] == ["end_turn"]
        assert resp.payload["latency_ms"] >= 0

    def test_tool_use_blocks_become_tool_call_events(self, store):
        response = FakeResponse(
            stop_reason="tool_use",
            content=[
                FakeBlock(type="text", text="checking"),
                FakeBlock(
                    type="tool_use", name="lookup_order", id="tu_1", input={"order_id": "1234"}
                ),
            ],
        )
        client = instrument(FakeClient(response), store=store, app="t")
        client.messages.create(**REQUEST_KWARGS)
        calls = events_by_type(store)[EventType.TOOL_CALL]
        assert len(calls) == 1
        assert calls[0].payload["gen_ai.tool.name"] == "lookup_order"
        assert calls[0].payload["input"] == {"order_id": "1234"}

    def test_tool_results_in_last_message_recorded(self, store):
        client = instrument(FakeClient(), store=store, app="t")
        kwargs = dict(REQUEST_KWARGS)
        kwargs["messages"] = [
            {"role": "user", "content": "hi"},
            {
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": "tu_1", "content": "shipped"}
                ],
            },
        ]
        client.messages.create(**kwargs)
        results = events_by_type(store)[EventType.TOOL_RESULT]
        assert len(results) == 1
        assert results[0].payload == {
            "tool_use_id": "tu_1",
            "content": "shipped",
            "is_error": False,
        }

    def test_unattributed_without_session_context(self, store):
        client = instrument(FakeClient(), store=store, app="t")
        client.messages.create(**REQUEST_KWARGS)
        assert all(e.session_id == "unattributed" for e in store.events())

    def test_non_messages_attributes_pass_through(self, store):
        client = instrument(FakeClient(), store=store, app="t")
        assert client.api_key == "sk-fake"


class TestFailOpen:
    class ExplodingStore:
        path = "nowhere"

        def append(self, **kwargs):
            raise RuntimeError("disk on fire")

    def test_store_failure_never_reaches_the_app(self, store):
        fake = FakeClient()
        client = instrument(fake, store=self.ExplodingStore(), app="t")
        response = client.messages.create(**REQUEST_KWARGS)  # must not raise
        assert response is fake.messages.response

    def test_dropped_events_flush_when_store_recovers(self, store):
        client = instrument(FakeClient(), store=store, app="t")
        sensor = client.messages._sensor

        real_append = store.append
        def broken_append(**kwargs):
            raise RuntimeError("db locked")

        store.append = broken_append
        client.messages.create(**REQUEST_KWARGS)  # request+response both dropped
        assert sensor.dropped == 2

        store.append = real_append
        client.messages.create(**REQUEST_KWARGS)
        dropped_events = events_by_type(store)[EventType.SENSOR_DROPPED]
        assert dropped_events[0].payload["count"] == 2
        assert sensor.dropped == 0

    def test_payload_serializer_crash_is_contained(self, store):
        class EvilResponse:
            id = "msg_evil"
            model = "claude-opus-4-8"
            stop_reason = "end_turn"

            @property
            def usage(self):
                raise RuntimeError("boom")

            content: list = []

        fake = FakeClient()
        fake.messages.response = EvilResponse()
        client = instrument(fake, store=store, app="t")
        response = client.messages.create(**REQUEST_KWARGS)  # must not raise
        assert response is fake.messages.response


class TestStream:
    class FakeStream:
        def __init__(self, final):
            self._final = final
            self.text_stream = iter(["hi ", "there"])

        def get_final_message(self):
            return self._final

    class FakeStreamCM:
        def __init__(self, stream):
            self._stream = stream

        def __enter__(self):
            return self._stream

        def __exit__(self, *exc):
            return False

    def test_stream_records_request_and_final_response(self, store):
        final = FakeResponse()
        fake = FakeClient()
        fake.messages.stream = lambda **kw: self.FakeStreamCM(self.FakeStream(final))
        client = instrument(fake, store=store, app="t")

        with client.messages.stream(**REQUEST_KWARGS) as stream:
            consumed = "".join(stream.text_stream)
        assert consumed == "hi there"

        by_type = events_by_type(store)
        assert len(by_type[EventType.LLM_REQUEST]) == 1
        assert len(by_type[EventType.LLM_RESPONSE]) == 1
