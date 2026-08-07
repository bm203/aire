"""Claude Code transcript importer tests.

Fixtures are synthetic and mirror the transcript's real record shapes. Real
transcripts are never used here: they contain whatever the developer typed,
read, or ran, which is exactly the sensitive material AIRE is meant to find.
"""

import json

import pytest

from aire.collectors.claude_code import DEFAULT_APP, import_transcript
from aire.core.events import EventType
from aire.store import EvidenceStore


@pytest.fixture
def store(tmp_path):
    s = EvidenceStore(tmp_path / "evidence.db")
    yield s
    s.close()


def write_transcript(tmp_path, records, name="session.jsonl"):
    path = tmp_path / name
    path.write_text("\n".join(json.dumps(r) for r in records), encoding="utf-8")
    return path


def user_prompt(text, **kw):
    return {
        "type": "user",
        "sessionId": "sess-1",
        "timestamp": "2026-07-28T10:00:00Z",
        "uuid": "u1",
        "cwd": "/home/dev/project",
        "gitBranch": "main",
        "message": {"role": "user", "content": text},
        **kw,
    }


def assistant(blocks, **kw):
    return {
        "type": "assistant",
        "sessionId": "sess-1",
        "timestamp": "2026-07-28T10:00:01Z",
        "uuid": "a1",
        "cwd": "/home/dev/project",
        "message": {
            "role": "assistant",
            "id": "msg_1",
            "model": "claude-opus-4-8",
            "stop_reason": "tool_use",
            "usage": {"input_tokens": 120, "output_tokens": 30},
            "content": blocks,
        },
        **kw,
    }


def tool_results(blocks, **kw):
    return {
        "type": "user",
        "sessionId": "sess-1",
        "timestamp": "2026-07-28T10:00:02Z",
        "uuid": "u2",
        "message": {"role": "user", "content": blocks},
        **kw,
    }


def events_by_type(store):
    grouped = {}
    for e in store.events():
        grouped.setdefault(e.event_type, []).append(e)
    return grouped


class TestMapping:
    def test_prompt_becomes_llm_request(self, tmp_path, store):
        path = write_transcript(tmp_path, [user_prompt("refactor the auth module")])
        import_transcript(path, store=store)
        [req] = events_by_type(store)[EventType.LLM_REQUEST]
        assert req.session_id == "sess-1"
        assert req.app == DEFAULT_APP
        assert req.payload["messages"][0]["content"] == "refactor the auth module"
        assert req.payload["source.cwd"] == "/home/dev/project"
        assert req.payload["source.timestamp"] == "2026-07-28T10:00:00Z"

    def test_assistant_response_and_tool_calls(self, tmp_path, store):
        path = write_transcript(
            tmp_path,
            [
                assistant(
                    [
                        {"type": "thinking", "thinking": "internal reasoning"},
                        {"type": "text", "text": "Running the tests."},
                        {
                            "type": "tool_use",
                            "id": "tu_1",
                            "name": "Bash",
                            "input": {"command": "pytest -q"},
                        },
                    ]
                )
            ],
        )
        import_transcript(path, store=store)
        by_type = events_by_type(store)

        [resp] = by_type[EventType.LLM_RESPONSE]
        assert resp.payload["gen_ai.response.model"] == "claude-opus-4-8"
        assert resp.payload["gen_ai.usage.input_tokens"] == 120
        assert resp.payload["content"] == "Running the tests."
        # reasoning is counted but never stored
        assert resp.payload["block_counts"]["thinking"] == 1
        assert "internal reasoning" not in json.dumps(resp.payload)

        [call] = by_type[EventType.TOOL_CALL]
        assert call.payload["gen_ai.tool.name"] == "Bash"
        assert call.payload["input"]["command"] == "pytest -q"

    def test_tool_result_is_linked_back_to_its_tool_name(self, tmp_path, store):
        path = write_transcript(
            tmp_path,
            [
                assistant(
                    [
                        {
                            "type": "tool_use",
                            "id": "tu_9",
                            "name": "WebFetch",
                            "input": {"url": "https://example.com/doc"},
                        }
                    ]
                ),
                tool_results(
                    [
                        {
                            "type": "tool_result",
                            "tool_use_id": "tu_9",
                            "content": [{"type": "text", "text": "page body"}],
                        }
                    ]
                ),
            ],
        )
        import_transcript(path, store=store)
        [result] = events_by_type(store)[EventType.TOOL_RESULT]
        # the transcript links these by id only; the importer restores the name
        # so findings can say which tool produced the content
        assert result.payload["gen_ai.tool.name"] == "WebFetch"
        assert result.payload["content"] == "page body"

    def test_model_is_carried_from_responses_onto_later_requests(self, tmp_path, store):
        """The transcript records the model on responses only, but it is a
        session-level property, so requests after the first response carry it."""
        path = write_transcript(
            tmp_path,
            [
                user_prompt("first prompt"),  # before any response: no model known
                assistant([{"type": "text", "text": "hello"}]),
                user_prompt("second prompt"),
            ],
        )
        import_transcript(path, store=store)
        first, second = events_by_type(store)[EventType.LLM_REQUEST]
        assert "gen_ai.request.model" not in first.payload
        assert second.payload["gen_ai.request.model"] == "claude-opus-4-8"

    def test_app_name_override(self, tmp_path, store):
        path = write_transcript(tmp_path, [user_prompt("hi")])
        import_transcript(path, store=store, app="dev-laptop-agent")
        assert all(e.app == "dev-laptop-agent" for e in store.events())


class TestRobustness:
    def test_unknown_record_types_are_skipped_and_counted(self, tmp_path, store):
        path = write_transcript(
            tmp_path,
            [
                {"type": "file-history-snapshot", "sessionId": "sess-1"},
                {"type": "ai-title", "sessionId": "sess-1"},
                user_prompt("hello"),
            ],
        )
        stats = import_transcript(path, store=store)
        assert stats.events_written == 1
        assert stats.skipped_by_type["file-history-snapshot"] == 1
        assert stats.skipped_by_type["ai-title"] == 1

    def test_malformed_lines_are_counted_not_fatal(self, tmp_path, store):
        path = tmp_path / "broken.jsonl"
        path.write_text(
            "\n".join(["{not valid json", json.dumps(user_prompt("still works"))]),
            encoding="utf-8",
        )
        stats = import_transcript(path, store=store)
        assert stats.malformed_lines == 1
        assert stats.events_written == 1

    def test_oversized_payloads_are_truncated(self, tmp_path, store):
        huge = "A" * 5_000
        path = write_transcript(tmp_path, [user_prompt(huge)])
        stats = import_transcript(path, store=store, max_payload_chars=1_000)
        [req] = events_by_type(store)[EventType.LLM_REQUEST]
        content = req.payload["messages"][0]["content"]
        assert len(content) < len(huge)
        assert "truncated" in content
        assert stats.truncated_payloads == 1

    def test_missing_transcript_raises(self, tmp_path, store):
        with pytest.raises(FileNotFoundError):
            import_transcript(tmp_path / "nope.jsonl", store=store)

    def test_import_is_fail_loud_unlike_live_collection(self, tmp_path):
        """A live collector swallows store errors; an import must not."""

        class ExplodingStore:
            path = "nowhere"
            read_only = False

            def append(self, **kwargs):
                raise RuntimeError("disk full")

        path = write_transcript(tmp_path, [user_prompt("hello")])
        with pytest.raises(RuntimeError):
            import_transcript(path, store=ExplodingStore())


class TestChainIntegrity:
    def test_imported_events_form_a_verifiable_chain(self, tmp_path, store):
        path = write_transcript(
            tmp_path,
            [
                user_prompt("check the logs"),
                assistant(
                    [
                        {"type": "text", "text": "on it"},
                        {
                            "type": "tool_use",
                            "id": "tu_1",
                            "name": "Bash",
                            "input": {"command": "tail -n 20 app.log"},
                        },
                    ]
                ),
                tool_results(
                    [{"type": "tool_result", "tool_use_id": "tu_1", "content": "no errors"}]
                ),
            ],
        )
        stats = import_transcript(path, store=store)
        assert stats.events_written == 4  # request, response, tool call, tool result
        assert store.verify().ok
