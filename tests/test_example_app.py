"""Import smoke test for the example app (skipped without the extras)."""

import importlib
import sys

import pytest


def test_example_app_imports_and_declares_routes(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("anthropic")
    pytest.importorskip("langgraph.checkpoint.sqlite")

    monkeypatch.setenv("AIRE_EVIDENCE_DB", str(tmp_path / "evidence.db"))
    monkeypatch.setenv("AIRE_MEMORY_DB", str(tmp_path / "memory.db"))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-real")

    sys.modules.pop("examples.support_agent.app", None)
    mod = importlib.import_module("examples.support_agent.app")

    routes = {r.path for r in mod.app.routes}
    assert {"/chat", "/health", "/memory/{session_id}"} <= routes
    # evidence store landed where the env said, not in the repo
    assert (tmp_path / "evidence.db").exists()
