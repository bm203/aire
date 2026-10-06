"""Codex rollout importer tests.

Fixtures are synthetic and mirror the rollout's serialized shapes as defined in
the open-source Codex code (RolloutLine / RolloutItem / ResponseItem). Real
rollouts are never used here: they contain whatever the developer typed, read,
or ran.
"""

import json

import pytest

from aire.collectors.codex import DEFAULT_APP, import_rollout
from aire.core.events import EventType
from aire.store import EvidenceStore

THREAD = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"
NAME = f"rollout-2026-10-01T09-30-00-{THREAD}.jsonl"


@pytest.fixture
def store(tmp_path):
    s = EvidenceStore(tmp_path / "evidence.db")
    yield s
    s.close()


def write_rollout(tmp_path, records, name=NAME):
    path = tmp_path / name
    path.write_text("\n".join(json.dumps(r) for r in records), encoding="utf-8")
    return path


def line(rtype, payload, ts="2026-10-01T09:30:01.000Z", **kw):
    return {"timestamp": ts, "type": rtype, "payload": payload, **kw}


def meta(**kw):
    return line("session_meta", {
        "id": THREAD,
        "session_id": THREAD,
        "timestamp": "2026-10-01T09:30:00.000Z",
        "cwd": "/home/dev/project",
        "originator": "codex_cli_rs",
        "cli_version": "0.120.0",
        "source": "cli",
        "git": {"commit_hash": "abc123", "branch": "main"},
        **kw,
    })


def turn(model="gpt-5.5-codex"):
    return line("turn_context", {
        "cwd": "/home/dev/project",
        "approval_policy": "on-request",
        "sandbox_policy": {"type": "workspace-write"},
        "model": model,
    })


def message(role, text, kind=None):
    kind = kind or ("output_text" if role == "assistant" else "input_text")
    return line("response_item", {"type": "message", "role": role,
                                  "content": [{"type": kind, "text": text}]})


def function_call(name, arguments, call_id="call_1"):
    return line("response_item", {"type": "function_call", "name": name,
                                  "arguments": arguments, "call_id": call_id})


def function_output(output, call_id="call_1"):
    return line("response_item", {"type": "function_call_output", "call_id": call_id,
                                  "output": output})


def events_by_type(store):
    grouped = {}
    for e in store.events():
        grouped.setdefault(e.event_type, []).append(e)
    return grouped


class TestMapping:
    def test_user_message_becomes_llm_request_with_turn_model(self, tmp_path, store):
        path = write_rollout(tmp_path, [meta(), turn(), message("user", "fix the failing test")])
        import_rollout(path, store=store)
        (req,) = events_by_type(store)[EventType.LLM_REQUEST]
        assert req.payload["messages"] == [{"role": "user", "content": "fix the failing test"}]
        assert req.payload["gen_ai.system"] == "openai"
        assert req.payload["gen_ai.request.model"] == "gpt-5.5-codex"
        assert req.session_id == THREAD and req.app == DEFAULT_APP

    def test_assistant_message_becomes_llm_response(self, tmp_path, store):
        path = write_rollout(tmp_path, [meta(), turn(), message("assistant", "Done.")])
        import_rollout(path, store=store)
        (resp,) = events_by_type(store)[EventType.LLM_RESPONSE]
        assert resp.payload["content"] == "Done."
        assert resp.payload["gen_ai.response.model"] == "gpt-5.5-codex"

    def test_function_call_arguments_are_parsed_and_output_linked(self, tmp_path, store):
        args = json.dumps({"cmd": "pytest -q", "workdir": "/home/dev/project"})
        path = write_rollout(tmp_path, [
            meta(), turn(), function_call("exec_command", args), function_output("3 passed"),
        ])
        import_rollout(path, store=store)
        grouped = events_by_type(store)
        (call,) = grouped[EventType.TOOL_CALL]
        (result,) = grouped[EventType.TOOL_RESULT]
        assert call.payload["gen_ai.tool.name"] == "exec_command"
        assert call.payload["input"] == {"cmd": "pytest -q", "workdir": "/home/dev/project"}
        assert result.payload["gen_ai.tool.name"] == "exec_command"
        assert result.payload["tool_use_id"] == "call_1"
        assert result.payload["content"] == "3 passed"
        assert result.payload["is_error"] is None  # not persisted by Codex

    def test_unparseable_arguments_are_kept_raw(self, tmp_path, store):
        path = write_rollout(tmp_path, [meta(), function_call("exec_command", "{not json")])
        import_rollout(path, store=store)
        (call,) = events_by_type(store)[EventType.TOOL_CALL]
        assert call.payload["input"] == "{not json"

    def test_custom_tool_call_and_structured_output(self, tmp_path, store):
        patch = "*** Begin Patch\n*** Update File: app.py\n*** End Patch"
        path = write_rollout(tmp_path, [
            meta(),
            line("response_item", {"type": "custom_tool_call", "name": "apply_patch",
                                   "input": patch, "call_id": "call_2"}),
            line("response_item", {"type": "custom_tool_call_output", "call_id": "call_2",
                                   "output": [{"type": "input_text", "text": "Success."}]}),
        ])
        import_rollout(path, store=store)
        grouped = events_by_type(store)
        assert grouped[EventType.TOOL_CALL][0].payload["input"] == patch
        result = grouped[EventType.TOOL_RESULT][0].payload
        assert result["gen_ai.tool.name"] == "apply_patch" and result["content"] == "Success."

    def test_typed_tools_get_a_name(self, tmp_path, store):
        path = write_rollout(tmp_path, [
            meta(),
            line("response_item", {"type": "local_shell_call", "call_id": "c3",
                                   "status": "completed",
                                   "action": {"type": "exec", "command": ["ls", "-la"]}}),
            line("response_item", {"type": "web_search_call", "status": "completed",
                                   "action": {"type": "search", "query": "cel spec"}}),
        ])
        import_rollout(path, store=store)
        names = [e.payload["gen_ai.tool.name"] for e in events_by_type(store)[EventType.TOOL_CALL]]
        assert names == ["local_shell", "web_search"]

    def test_inter_agent_message_is_scanned_as_tool_result(self, tmp_path, store):
        path = write_rollout(tmp_path, [meta(), line("response_item", {
            "type": "agent_message", "author": "worker-1", "recipient": "root",
            "content": [{"type": "input_text", "text": "found the bug"}]})])
        import_rollout(path, store=store)
        (result,) = events_by_type(store)[EventType.TOOL_RESULT]
        assert result.payload["gen_ai.tool.name"] == "agent_message"
        assert result.payload["codex.author"] == "worker-1"

    def test_provenance_is_kept(self, tmp_path, store):
        path = write_rollout(tmp_path, [meta(), message("user", "hi")])
        import_rollout(path, store=store)
        (req,) = store.events()
        assert req.payload["source.type"] == "codex-rollout"
        assert req.payload["source.timestamp"] == "2026-10-01T09:30:01.000Z"
        assert req.payload["source.cwd"] == "/home/dev/project"
        assert req.payload["source.git_branch"] == "main"
        assert req.payload["source.cli_version"] == "0.120.0"


class TestCoverage:
    def test_non_behaviour_items_are_skipped_and_counted(self, tmp_path, store):
        path = write_rollout(tmp_path, [
            meta(), turn(),
            message("developer", "<permissions instructions>"),
            line("response_item", {"type": "reasoning", "summary": [], "encrypted_content": "x"}),
            line("event_msg", {"type": "agent_message", "message": "Done."}),
            line("compacted", {"message": "summary"}),
            line("some_future_type", {"x": 1}),
            message("user", "go"),
        ])
        stats = import_rollout(path, store=store)
        assert stats.events_written == 1
        assert stats.skipped_by_type == {
            "session_meta": 1, "turn_context": 1, "response_item:message:developer": 1,
            "response_item:reasoning": 1, "event_msg": 1, "compacted": 1, "some_future_type": 1,
        }

    def test_session_id_falls_back_to_file_name(self, tmp_path, store):
        path = write_rollout(tmp_path, [message("user", "no meta line")])
        stats = import_rollout(path, store=store)
        assert stats.sessions == {THREAD}

    def test_app_name_override(self, tmp_path, store):
        path = write_rollout(tmp_path, [message("user", "hi")])
        import_rollout(path, store=store, app="codex-ci")
        assert next(iter(store.events())).app == "codex-ci"

    def test_malformed_lines_are_counted_not_fatal(self, tmp_path, store):
        path = tmp_path / NAME
        path.write_text(json.dumps(message("user", "ok")) + "\n{broken\n[1, 2]\n")
        stats = import_rollout(path, store=store)
        assert stats.malformed_lines == 2 and stats.events_written == 1

    def test_oversized_payloads_are_truncated(self, tmp_path, store):
        path = write_rollout(tmp_path, [meta(), function_call("exec_command", "{}"),
                                        function_output("x" * 500)])
        stats = import_rollout(path, store=store, max_payload_chars=100)
        (result,) = events_by_type(store)[EventType.TOOL_RESULT]
        assert result.payload["content"].startswith("x" * 100)
        assert "truncated, 400 more" in result.payload["content"]
        assert stats.truncated_payloads == 1

    def test_compressed_rollout_is_refused_loudly(self, tmp_path, store):
        path = tmp_path / (NAME + ".zst")
        path.write_bytes(b"\x28\xb5\x2f\xfd")
        with pytest.raises(ValueError, match="zstd -d"):
            import_rollout(path, store=store)

    def test_missing_rollout_raises(self, tmp_path, store):
        with pytest.raises(FileNotFoundError):
            import_rollout(tmp_path / "nope.jsonl", store=store)

    def test_imported_events_form_a_verifiable_chain(self, tmp_path, store):
        path = write_rollout(tmp_path, [meta(), turn(), message("user", "a"),
                                        function_call("exec_command", "{}"), function_output("b"),
                                        message("assistant", "c")])
        import_rollout(path, store=store)
        assert store.verify().ok


class TestCli:
    def test_import_codex_command(self, tmp_path):
        from typer.testing import CliRunner

        from aire.cli import app

        path = write_rollout(tmp_path, [meta(), message("user", "hi")])
        r = CliRunner().invoke(app, ["import-codex", str(path), str(tmp_path / "e.db")])
        assert r.exit_code == 0, r.output
        assert "imported 1 event(s)" in r.output

    def test_compressed_rollout_exits_with_instruction(self, tmp_path):
        from typer.testing import CliRunner

        from aire.cli import app

        path = tmp_path / (NAME + ".zst")
        path.write_bytes(b"\x28\xb5\x2f\xfd")
        r = CliRunner().invoke(app, ["import-codex", str(path), str(tmp_path / "e.db")])
        assert r.exit_code == 2
        assert "zstd -d" in r.output
