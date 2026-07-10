#!/usr/bin/env python
"""Repeatable LIVE validation of AIRE's collectors against the real Anthropic API.

⚠️  This makes REAL API calls (a few small ones — cents) and needs
    ANTHROPIC_API_KEY in the environment. It is NOT run in CI; run it by hand
    after an Anthropic SDK / LangGraph upgrade to confirm the duck-typed
    collectors still match the real SDK surface.

Requires the anthropic + langgraph extras (pii optional, for the pipeline step):

    pip install -e ".[anthropic,langgraph,pii]"
    export ANTHROPIC_API_KEY=...        # or via direnv / .env
    python scripts/live_validation.py

What it checks, end to end, on real SDK objects:
  A. Anthropic collector — streaming path (client.messages.stream).
  B. Anthropic collector — non-streaming + tool use (create → tool_use → result).
  C. LangGraph collector — a real StateGraph run driving the instrumented
     checkpointer, with the instrumented raw client inside the node.
Then it runs the full pipeline (policy + detectors + report + verify) over the
captured evidence and confirms the hash chain is intact.

All data is synthetic (example.com / reserved asset ids). The API key is never
printed. Exit code 0 = pass, 1 = a capture/verify assertion failed.
"""

from __future__ import annotations

import os
import sqlite3
import tempfile
from collections import Counter
from pathlib import Path
from typing import TypedDict

MODEL = os.environ.get("AIRE_LIVE_MODEL", "claude-opus-4-8")
_MAX_TOKENS = 64


def _fail(msg: str) -> None:
    print(f"  FAIL: {msg}")


def main() -> int:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("ANTHROPIC_API_KEY not set — export it (or use direnv/.env) and re-run.")
        return 2

    import anthropic
    from langgraph.checkpoint.sqlite import SqliteSaver
    from langgraph.graph import END, START, StateGraph

    from aire.collectors import session
    from aire.collectors.anthropic_sdk import instrument
    from aire.collectors.langgraph import InstrumentedSaver
    from aire.core.events import EventType
    from aire.store import EvidenceStore

    tmp = tempfile.mkdtemp(prefix="aire-live-")
    store = EvidenceStore(Path(tmp) / "evidence.db")
    client = instrument(anthropic.Anthropic(), store=store, app="live-validation")
    ok = True

    # --- A. streaming --------------------------------------------------------
    print(f"[A] streaming collector path (model={MODEL}) ...")
    with session("stream"):
        with client.messages.stream(
            model=MODEL, max_tokens=_MAX_TOKENS,
            messages=[{"role": "user", "content": "Say hello in four words."}],
        ) as stream:
            "".join(stream.text_stream)
    a_req = list(store.events(session_id="stream", event_type=EventType.LLM_REQUEST))
    a_resp = list(store.events(session_id="stream", event_type=EventType.LLM_RESPONSE))
    a_tokens = a_resp[0].payload.get("gen_ai.usage.output_tokens") if a_resp else None
    if len(a_req) == 1 and len(a_resp) == 1 and a_tokens:
        print(f"    ok — captured request + response (out_tokens={a_tokens})")
    else:
        ok = False
        _fail(f"streaming capture: req={len(a_req)} resp={len(a_resp)}")

    # --- B. non-streaming + tool use ----------------------------------------
    print("[B] non-streaming + tool-use capture ...")
    tools = [
        {
            "name": "lookup_asset",
            "description": "Look up an industrial asset's status by id.",
            "input_schema": {
                "type": "object",
                "properties": {"asset_id": {"type": "string"}},
                "required": ["asset_id"],
            },
        }
    ]
    with session("tooluse"):
        messages = [{"role": "user", "content": "What is the status of asset PUMP-STN-07?"}]
        resp = client.messages.create(
            model=MODEL, max_tokens=256, tools=tools, messages=messages
        )
        if resp.stop_reason == "tool_use":
            assistant = [b.model_dump() for b in resp.content]
            messages.append({"role": "assistant", "content": assistant})
            results = [
                {"type": "tool_result", "tool_use_id": b.id, "content": "status: nominal"}
                for b in resp.content
                if b.type == "tool_use"
            ]
            messages.append({"role": "user", "content": results})
            client.messages.create(
                model=MODEL, max_tokens=_MAX_TOKENS, tools=tools, messages=messages
            )
    b_calls = list(store.events(session_id="tooluse", event_type=EventType.TOOL_CALL))
    b_results = list(store.events(session_id="tooluse", event_type=EventType.TOOL_RESULT))
    if b_calls and b_results:
        tool_name = b_calls[0].payload.get("gen_ai.tool.name")
        print(f"    ok — tool.call={len(b_calls)} (name={tool_name}) "
              f"tool.result={len(b_results)}")
    else:
        ok = False
        _fail(f"tool-use capture: calls={len(b_calls)} results={len(b_results)} "
              f"(stop_reason may have been end_turn — re-run)")

    # --- C. LangGraph collector via a real StateGraph run -------------------
    print("[C] LangGraph collector through a real StateGraph run ...")
    conn = sqlite3.connect(Path(tmp) / "memory.db", check_same_thread=False)
    saver = InstrumentedSaver(SqliteSaver(conn), store=store, app="live-validation")

    class GS(TypedDict):
        question: str
        answer: str

    def node(state: GS) -> dict:
        with session("graph"):
            r = client.messages.create(
                model=MODEL, max_tokens=_MAX_TOKENS,
                messages=[{"role": "user", "content": state["question"]}],
            )
        return {"answer": next((b.text for b in r.content if b.type == "text"), "")}

    g = StateGraph(GS)
    g.add_node("answer", node)
    g.add_edge(START, "answer")
    g.add_edge("answer", END)
    app = g.compile(checkpointer=saver)
    cfg = {"configurable": {"thread_id": "graph"}}
    app.invoke({"question": "Name one industrial asset type in three words."}, cfg)
    app.invoke({"question": "And one more, three words."}, cfg)  # second invoke → memory.read
    c_writes = list(store.events(event_type=EventType.MEMORY_WRITE))
    c_reads = list(store.events(event_type=EventType.MEMORY_READ))
    if c_writes and c_reads:
        print(f"    ok — memory.write={len(c_writes)} memory.read={len(c_reads)} (graph-driven)")
    else:
        ok = False
        _fail(f"langgraph capture: writes={len(c_writes)} reads={len(c_reads)}")

    # --- pipeline + chain verify --------------------------------------------
    print("[pipeline] policy + detectors + report + verify over the live evidence ...")
    try:
        from aire.detectors import CompletenessDetector, DetectorRunner, PromptInjectionDetector
        from aire.policy import PolicyEngine, builtin_policies
        from aire.report import build_report

        detectors = [PromptInjectionDetector(), CompletenessDetector()]
        try:
            from aire.detectors.pii import PIIDetector, PresidioScanner

            detectors.append(PIIDetector(scanner=PresidioScanner()))
        except ImportError:
            print("    (pii extra not installed — skipping PII detector)")
        PolicyEngine(builtin_policies()).run(store)
        DetectorRunner(detectors).run(store)
        report = build_report(store, title="AIRE live validation")
        print(f"    report: risk={report.overall_risk_level.value} events={report.total_events}")
    except Exception as exc:  # pipeline is secondary to capture validation
        print(f"    (pipeline step raised: {type(exc).__name__}: {exc})")

    v = store.verify()
    if not v.ok:
        ok = False
        _fail(f"chain verify: {v.reason} at seq {v.first_bad_seq}")

    types = Counter(e.event_type.value for e in store.events())
    store.close()
    conn.close()

    print("\ncaptured event types:", dict(sorted(types.items())))
    print(f"chain: {'intact' if v.ok else 'BROKEN'} ({v.checked} events)")
    print("\nRESULT:", "PASS — collectors validated live" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
