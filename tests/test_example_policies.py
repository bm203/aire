"""Shipped example policy packs must load, compile, and do what they say."""

import json
from pathlib import Path

import pytest

from aire.collectors.codex import import_rollout
from aire.core.events import EventType
from aire.policy import PolicyEngine, Verdict, load_policies
from aire.store import EvidenceStore

PACKS = sorted((Path(__file__).parent.parent / "examples" / "policies").glob("*.yaml"))


@pytest.mark.parametrize("pack", PACKS, ids=lambda p: p.name)
def test_example_pack_compiles(pack):
    engine = PolicyEngine(load_policies(pack))
    assert engine.policies


def test_codex_pack_flags_what_it_claims(tmp_path):
    def call(name, call_id):
        return {"timestamp": "t", "type": "response_item",
                "payload": {"type": "function_call", "name": name, "arguments": "{}",
                            "call_id": call_id}}

    path = tmp_path / "rollout.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in [
        call("exec_command", "1"), call("request_permissions", "2"), call("mcp__drive__read", "3"),
        {"timestamp": "t", "type": "response_item",
         "payload": {"type": "web_search_call", "action": {"type": "search", "query": "q"}}},
    ]))
    store = EvidenceStore(tmp_path / "e.db")
    import_rollout(path, store=store)
    engine = PolicyEngine(load_policies(PACKS[[p.name for p in PACKS].index("codex.yaml")]))
    failed = {}
    for event in store.events(event_type=EventType.TOOL_CALL):
        for r in engine.evaluate_event(event):
            if r.verdict == Verdict.FAIL:
                failed.setdefault(event.payload["gen_ai.tool.name"], set()).add(r.policy_id)
    store.close()
    assert "exec_command" not in failed
    assert failed["mcp__drive__read"] == {"CODEX_TOOL_ALLOWLIST"}
    assert failed["request_permissions"] == {"CODEX_TOOL_ALLOWLIST", "CODEX_PERMISSION_ESCALATION"}
    assert failed["web_search"] == {"CODEX_EXTERNAL_CONTENT_FETCHED"}
