# Example: instrumented support agent

A minimal customer-support agent showing AIRE's observe-only pipeline end to
end: Anthropic API calls with tool use, conversation memory in a LangGraph
`SqliteSaver` checkpointer, and every interaction recorded to a hash-chained
evidence store.

## Run

```bash
pip install -e ".[examples]"
export ANTHROPIC_API_KEY=...      # or set it in your .envrc
uvicorn examples.support_agent.app:app --reload
```

## Try it

```bash
# A conversation with a tool call (order lookup)
curl -s localhost:8000/chat -X POST -H 'content-type: application/json' \
  -d '{"session_id": "demo-1", "message": "Where is my order #1234?"}'

# Follow-up in the same session (memory read + write)
curl -s localhost:8000/chat -X POST -H 'content-type: application/json' \
  -d '{"session_id": "demo-1", "message": "And when will it arrive?"}'

# Erasure request (memory.delete event)
curl -s -X DELETE localhost:8000/memory/demo-1

# Inspect the evidence
aire verify support_agent_evidence.db
```

Every prompt, response, tool call, tool result, and memory operation is now
an event in `support_agent_evidence.db` — append-only and hash-chained.
Tamper with the file and `aire verify` will name the broken event.

Environment knobs: `AIRE_EXAMPLE_MODEL` (default `claude-opus-4-8`),
`AIRE_EVIDENCE_DB`, `AIRE_MEMORY_DB`.
