"""Policy engine tests: loader, CEL backend, engine semantics, CLI."""

import pytest

from aire.core.events import EventType
from aire.policy import (
    CELBackend,
    PolicyEngine,
    PolicyLoadError,
    Verdict,
    builtin_policies,
    load_policies,
)
from aire.policy.backend import ExpressionCompileError, ExpressionEvalError
from aire.policy.engine import PolicyCompileError
from aire.store import EvidenceStore

VALID_YAML = """
policies:
  - id: TOOL_ALLOWLIST
    description: Only approved tools.
    severity: high
    applies_to: [tool.call]
    params:
      allowed_tools: ["lookup_order"]
    violation: '!(payload["gen_ai.tool.name"] in params.allowed_tools)'
    framework_refs: ["OWASP-LLM:LLM06"]
  - id: SESSION_ATTRIBUTION
    description: Events must be attributable.
    severity: low
    applies_to: [llm.request]
    verdict_on_violation: warn
    violation: 'event.session_id == "unattributed"'
"""


@pytest.fixture
def store(tmp_path):
    s = EvidenceStore(tmp_path / "evidence.db")
    yield s
    s.close()


@pytest.fixture
def policies(tmp_path):
    f = tmp_path / "policies.yaml"
    f.write_text(VALID_YAML)
    return load_policies(f)


def append_tool_call(store, tool="lookup_order", session_id="sess-1"):
    return store.append(
        session_id=session_id,
        app="t",
        event_type=EventType.TOOL_CALL,
        payload={"gen_ai.tool.name": tool, "tool_use_id": "tu_1"},
    )


class TestLoader:
    def test_loads_valid_file(self, policies):
        assert [p.id for p in policies] == ["TOOL_ALLOWLIST", "SESSION_ATTRIBUTION"]
        assert policies[0].severity == "high"
        assert policies[0].applies_to == [EventType.TOOL_CALL]
        assert policies[1].verdict_on_violation == Verdict.WARN

    def test_loads_directory_sorted(self, tmp_path):
        (tmp_path / "b.yaml").write_text(VALID_YAML.replace("TOOL_ALLOWLIST", "ZZZ_POLICY"))
        (tmp_path / "a.yaml").write_text(VALID_YAML.replace("SESSION_ATTRIBUTION", "AAA_POLICY"))
        loaded = load_policies(tmp_path)
        assert [p.id for p in loaded][:2] == ["TOOL_ALLOWLIST", "AAA_POLICY"]

    def test_missing_path_errors(self, tmp_path):
        with pytest.raises(PolicyLoadError, match="no such file"):
            load_policies(tmp_path / "nope.yaml")

    def test_invalid_yaml_names_file(self, tmp_path):
        f = tmp_path / "broken.yaml"
        f.write_text("policies: [{id: 'X', ")
        with pytest.raises(PolicyLoadError, match="broken.yaml"):
            load_policies(f)

    def test_missing_policies_key(self, tmp_path):
        f = tmp_path / "empty.yaml"
        f.write_text("rules: []")
        with pytest.raises(PolicyLoadError, match="top-level 'policies:'"):
            load_policies(f)

    def test_validation_error_names_policy_and_field(self, tmp_path):
        f = tmp_path / "bad.yaml"
        f.write_text(
            """
policies:
  - id: BAD_SEVERITY
    description: x
    severity: catastrophic
    applies_to: [tool.call]
    violation: 'true'
"""
        )
        with pytest.raises(PolicyLoadError, match=r"BAD_SEVERITY.*severity"):
            load_policies(f)

    def test_duplicate_ids_rejected(self, tmp_path):
        (tmp_path / "a.yaml").write_text(VALID_YAML)
        (tmp_path / "b.yaml").write_text(VALID_YAML)
        with pytest.raises(PolicyLoadError, match="duplicate policy id"):
            load_policies(tmp_path)

    def test_builtin_pack_loads_and_compiles(self):
        pack = builtin_policies()
        assert {p.id for p in pack} >= {
            "TOOL_ALLOWLIST",
            "TOOL_HUMAN_REVIEW",
            "MODEL_ALLOWLIST",
            "SESSION_ATTRIBUTION",
        }
        PolicyEngine(pack)  # must compile cleanly
        assert all(p.framework_refs for p in pack)


class TestCELBackend:
    def test_compile_and_evaluate(self):
        expr = CELBackend().compile('payload.x > 3')
        assert expr.evaluate({"payload": {"x": 5}}) is True
        assert expr.evaluate({"payload": {"x": 1}}) is False

    def test_parse_error(self):
        with pytest.raises(ExpressionCompileError):
            CELBackend().compile("this is (not CEL")

    def test_missing_key_is_eval_error(self):
        expr = CELBackend().compile('payload.missing == "x"')
        with pytest.raises(ExpressionEvalError):
            expr.evaluate({"payload": {}})

    def test_non_boolean_result_is_eval_error(self):
        expr = CELBackend().compile('payload.x + 1')
        with pytest.raises(ExpressionEvalError, match="boolean"):
            expr.evaluate({"payload": {"x": 1}})


class TestEngine:
    def test_bad_expression_fails_at_construction(self, policies):
        broken = policies[0].model_copy(update={"violation": "((("})
        with pytest.raises(PolicyCompileError, match="TOOL_ALLOWLIST"):
            PolicyEngine([broken])

    def test_violation_recorded_with_evidence_pointer(self, store, policies):
        bad = append_tool_call(store, tool="rm_rf_slash")
        outcome = PolicyEngine(policies).run(store)
        assert outcome.counts["fail"] == 1
        [recorded] = outcome.recorded
        p = recorded.payload
        assert p["policy_id"] == "TOOL_ALLOWLIST"
        assert p["verdict"] == "fail"
        assert p["source_event_id"] == bad.event_id
        assert p["source_event_hash"] == bad.hash
        assert p["framework_refs"] == ["OWASP-LLM:LLM06"]
        assert recorded.session_id == "sess-1"

    def test_pass_is_counted_but_not_recorded_per_event(self, store, policies):
        append_tool_call(store, tool="lookup_order")
        outcome = PolicyEngine(policies).run(store)
        assert outcome.counts["pass"] == 1
        assert outcome.recorded == []
        assert outcome.summary_event.payload["counts"]["pass"] == 1

    def test_warn_verdict(self, store, policies):
        store.append(
            session_id="unattributed",
            app="t",
            event_type=EventType.LLM_REQUEST,
            payload={"gen_ai.request.model": "claude-opus-4-8"},
        )
        outcome = PolicyEngine(policies).run(store)
        assert outcome.counts["warn"] == 1
        assert outcome.recorded[0].payload["verdict"] == "warn"

    def test_unevaluable_expression_yields_error_verdict(self, store, policies):
        # payload lacks gen_ai.tool.name → CEL key error → ERROR, not a crash
        store.append(
            session_id="s", app="t", event_type=EventType.TOOL_CALL, payload={"weird": True}
        )
        outcome = PolicyEngine(policies).run(store)
        assert outcome.counts["error"] == 1
        assert "NOT EVALUATED" in outcome.recorded[0].payload["explanation"]

    def test_rerun_is_idempotent(self, store, policies):
        append_tool_call(store, tool="rm_rf_slash")
        engine = PolicyEngine(policies)
        first = engine.run(store)
        assert len(first.recorded) == 1
        second = engine.run(store)
        assert second.recorded == []
        assert second.counts.get("already_recorded") == 1
        # exactly one violation + two run summaries on the chain
        results = list(store.events(event_type=EventType.POLICY_RESULT))
        assert len([e for e in results if e.payload.get("policy_id")]) == 1
        assert len([e for e in results if e.payload.get("op") == "run_summary"]) == 2

    def test_results_join_the_hash_chain(self, store, policies):
        append_tool_call(store, tool="rm_rf_slash")
        PolicyEngine(policies).run(store)
        assert store.verify().ok

    def test_session_filter(self, store, policies):
        append_tool_call(store, tool="rm_rf_slash", session_id="sess-A")
        append_tool_call(store, tool="rm_rf_slash", session_id="sess-B")
        outcome = PolicyEngine(policies).run(store, session_id="sess-A")
        assert len(outcome.recorded) == 1
        assert outcome.recorded[0].session_id == "sess-A"


class TestCli:
    def test_evaluate_command(self, store, tmp_path):
        from typer.testing import CliRunner

        from aire.cli import app

        append_tool_call(store, tool="rm_rf_slash")
        policy_file = tmp_path / "policies.yaml"
        policy_file.write_text(VALID_YAML)

        runner = CliRunner()
        result = runner.invoke(app, ["evaluate", str(store.path), "--policies", str(policy_file)])
        assert result.exit_code == 0
        assert "TOOL_ALLOWLIST" in result.output
        assert "[FAIL]" in result.output

    def test_evaluate_requires_some_policies(self, store):
        from typer.testing import CliRunner

        from aire.cli import app

        result = CliRunner().invoke(app, ["evaluate", str(store.path)])
        assert result.exit_code == 2

    def test_evaluate_builtin_flag(self, store):
        from typer.testing import CliRunner

        from aire.cli import app

        append_tool_call(store, tool="lookup_order")
        result = CliRunner().invoke(app, ["evaluate", str(store.path), "--builtin"])
        assert result.exit_code == 0
        assert "evaluated" in result.output
