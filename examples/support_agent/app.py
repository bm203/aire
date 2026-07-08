"""Example: customer-support agent instrumented by AIRE.

A minimal FastAPI app demonstrating the full observe-only pipeline:

- Anthropic API calls (with tool use) via the instrumented client
- conversation memory persisted in a LangGraph ``SqliteSaver`` checkpointer,
  wrapped by AIRE's ``InstrumentedSaver``
- every interaction lands in the hash-chained evidence store

Run (needs ANTHROPIC_API_KEY):

    pip install -e ".[examples]"
    uvicorn examples.support_agent.app:app --reload

Then:

    curl -s localhost:8000/chat -X POST -H 'content-type: application/json' \
      -d '{"session_id": "demo-1", "message": "Where is my order #1234?"}'
    curl -s -X DELETE localhost:8000/memory/demo-1
    aire verify support_agent_evidence.db
"""

from __future__ import annotations

import os
import sqlite3
from datetime import UTC, datetime
from typing import Any

import anthropic
from fastapi import FastAPI
from langgraph.checkpoint.sqlite import SqliteSaver
from pydantic import BaseModel
from ulid import ULID

from aire.collectors import session
from aire.collectors.anthropic_sdk import instrument
from aire.collectors.langgraph import InstrumentedSaver
from aire.store import EvidenceStore

APP_NAME = "support-agent"
MODEL = os.environ.get("AIRE_EXAMPLE_MODEL", "claude-opus-4-8")

EVIDENCE_DB = os.environ.get("AIRE_EVIDENCE_DB", "support_agent_evidence.db")
MEMORY_DB = os.environ.get("AIRE_MEMORY_DB", "support_agent_memory.db")

SYSTEM_PROMPT = (
    "You are a customer-support agent for Verlinkt Retail. Be brief and"
    " helpful. Use the lookup_order tool when the customer asks about an"
    " order; never invent order details."
)

TOOLS = [
    {
        "name": "lookup_order",
        "description": (
            "Look up an order by its numeric id. Call this whenever the"
            " customer asks about the status, contents, or delivery of an"
            " order."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "order_id": {"type": "string", "description": "Numeric order id, e.g. '1234'"}
            },
            "required": ["order_id"],
        },
    }
]

# Fake back-office data — this is a demo.
_ORDERS = {
    "1234": {"status": "shipped", "carrier": "DHL", "eta": "2026-07-10"},
    "5678": {"status": "processing", "carrier": None, "eta": "2026-07-14"},
}


def lookup_order(order_id: str) -> dict[str, Any]:
    return _ORDERS.get(order_id, {"status": "not_found"})


# --- wiring ----------------------------------------------------------------

store = EvidenceStore(EVIDENCE_DB)
client = instrument(anthropic.Anthropic(), store=store, app=APP_NAME)
_memory_conn = sqlite3.connect(MEMORY_DB, check_same_thread=False)
memory = InstrumentedSaver(SqliteSaver(_memory_conn), store=store, app=APP_NAME)

app = FastAPI(title="AIRE example: support agent")


class ChatRequest(BaseModel):
    session_id: str
    message: str


class ChatResponse(BaseModel):
    session_id: str
    reply: str


def _config(session_id: str) -> dict[str, Any]:
    return {"configurable": {"thread_id": session_id, "checkpoint_ns": ""}}


def _load_messages(session_id: str) -> list[dict[str, Any]]:
    saved = memory.get_tuple(_config(session_id))
    if saved is None:
        return []
    return list(saved.checkpoint.get("channel_values", {}).get("messages", []))


def _save_messages(session_id: str, messages: list[dict[str, Any]], step: int) -> None:
    checkpoint = {
        "v": 1,
        # ULIDs sort lexicographically by time, matching the checkpointer's
        # "latest = highest checkpoint_id" retrieval order.
        "id": str(ULID()),
        "ts": datetime.now(UTC).isoformat(),
        "channel_values": {"messages": messages},
        "channel_versions": {"messages": step},
        "versions_seen": {},
        "pending_sends": [],
    }
    memory.put(_config(session_id), checkpoint, {"source": "update", "step": step}, {})


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "app": APP_NAME}


@app.post("/chat", response_model=ChatResponse)
def chat(req: ChatRequest) -> ChatResponse:
    with session(req.session_id):
        messages = _load_messages(req.session_id)
        messages.append({"role": "user", "content": req.message})

        # Manual tool-use loop: call, execute requested tools, feed results
        # back, repeat until the model stops asking for tools.
        while True:
            response = client.messages.create(
                model=MODEL,
                max_tokens=16000,
                thinking={"type": "adaptive"},
                system=SYSTEM_PROMPT,
                tools=TOOLS,
                messages=messages,
            )
            messages.append(
                {"role": "assistant", "content": [b.model_dump() for b in response.content]}
            )
            if response.stop_reason != "tool_use":
                break
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    result = lookup_order(**block.input)
                    tool_results.append(
                        {"type": "tool_result", "tool_use_id": block.id, "content": str(result)}
                    )
            messages.append({"role": "user", "content": tool_results})

        _save_messages(req.session_id, messages, step=len(messages))

        reply = next((b.text for b in response.content if b.type == "text"), "")
        return ChatResponse(session_id=req.session_id, reply=reply)


@app.delete("/memory/{session_id}")
def delete_memory(session_id: str) -> dict[str, str]:
    """Delete a conversation's memory (GDPR-style erasure request).

    The deletion itself is recorded as a memory.delete event; AIRE's memory
    control can later verify the checkpointer really no longer holds the data.
    """
    memory.delete_thread(session_id)
    return {"status": "deleted", "session_id": session_id}
