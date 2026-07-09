# Architecture

AIRE turns runtime AI interactions into tamper-evident audit evidence,
evaluates that evidence against policy, and reports findings mapped to
governance controls. This document describes the module boundaries and the
data flow between them.

## Data flow

```
Collectors → AuditEvent → EvidenceStore (append-only, hash-chained)
                                │
      ┌─────────────────────────┼──────────────────────────┐
   PolicyEngine            DetectorRunner            MemoryRetentionControl
  (YAML → CEL)      (PII, injection, completeness)   (read-only cross-exam)
      └─────────────────────────┼──────────────────────────┘
                     policy.result / finding events
                     (appended to the same chain)
                                │
                          build_report → JSON / Markdown / HTML
```

Everything downstream of the collectors runs **out-of-band** — over the
stored evidence, never in the host application's request path.

## Modules

| Module | Responsibility |
|---|---|
| `aire.core.events` | The `AuditEvent` schema and the hash-chain primitives (canonical serialization, SHA-256 sealing). |
| `aire.core.types` | Shared `Severity` enum. |
| `aire.store` | `EvidenceStore`: append-only (trigger-enforced), hash-chained SQLite log; `verify()` walks and localizes chain breaks. |
| `aire.collectors` | Observe-only, fail-open instrumentation: `Sensor` (recording core), `anthropic_sdk.instrument`, `langgraph.InstrumentedSaver`, and `session()` attribution. |
| `aire.policy` | YAML policy surface → `PolicyBackend` (CEL) → `PolicyEngine`; the builtin starter pack. |
| `aire.detectors` | `Detector` interface + `DetectorRunner`; PII (Presidio), prompt injection, completeness, and the deep memory retention/deletion control. |
| `aire.mappings` | Framework citation YAML (EU AI Act / ISO 42001 / NIST AI RMF / OWASP) and ref resolution. |
| `aire.risk` | Transparent weighted risk score. |
| `aire.report` | `build_report` + JSON/Markdown/HTML renderers. |
| `aire.cli` | The `aire` command (`verify`, `evaluate`, `detect`, `report`, `mappings`). |

The core install is deliberately lean; collectors and the PII detector are
optional extras (`aire[anthropic]`, `aire[langgraph]`, `aire[pii]`) so the
evidence core carries no heavy dependencies.

## The event

Every observation is an immutable `AuditEvent` (frozen Pydantic model):

- **Envelope** — `event_id` (ULID, time-sortable), `ts`, `session_id`,
  `trace_id`, `app`, `event_type`.
- **Payload** — typed per event type; field names follow the OpenTelemetry
  GenAI semantic conventions where an equivalent exists
  (`gen_ai.request.model`, `gen_ai.usage.input_tokens`, …), so evidence can
  later be exported to OTel-native backends without renaming.
- **Chain fields** — `prev_hash` (the previous event's hash) and `hash`
  (SHA-256 over this event's canonical JSON, excluding `hash` itself).

Event types cover `llm.request/response`, `tool.call/result`,
`retrieval.context`, `memory.write/read/delete/expire`, `policy.result`,
`finding`, and `sensor.dropped`. **Findings and policy results are events
too**, so the audit conclusions are themselves in the tamper-evident chain.

## Two integrity layers

1. **Append-only at the database level** — triggers abort any `UPDATE` or
   `DELETE` on the events table, stopping accidental mutation through the
   normal write path.
2. **Hash chain** — an attacker with file access can drop the triggers and
   edit rows, but cannot do so without breaking the chain. `verify()` walks
   the chain and reports the first event whose `prev_hash` mismatches its
   predecessor or whose stored hash doesn't match a recomputation — pinning
   tampering, insertion, deletion, or reordering to a specific event.

## Fail-open sensor

The cardinal rule: **the sensor can never break the host application.**
Collectors call `Sensor.record()`, which builds the payload and writes to the
store inside a guard. Any failure is swallowed and counted; the dropped count
is flushed as a `sensor.dropped` event on the next successful write. Gaps in
the evidence therefore become evidence — the completeness detector turns them
into findings. Host-application errors always propagate untouched; AIRE only
ever swallows its *own* failures.

## The deep memory control

`MemoryRetentionControl` is the one control built to interview-defensible
depth. It cross-examines two independent sources:

- what the app **claimed** — the `memory.delete` / `memory.write` events the
  collector recorded in the tamper-evident chain, and
- what is **actually stored** — the LangGraph checkpointer database, opened
  through a strictly read-only SQLite connection (`mode=ro`).

From that it answers: was a recorded deletion actually honored (do rows
survive)?  Is any checkpoint older than the retention limit?  Is PII present
in stored memory?  Did a session read another session's memory?  Checkpoint
blobs are parsed by the checkpointer's own serializer, never by homegrown
blob parsing.

## Extending AIRE

- **A new collector** — wrap the host SDK/framework and call `Sensor.record()`
  with the right event type; keep it fail-open.
- **A new detector** — implement `Detector.inspect(events, store) -> [Finding]`
  and register it with the `DetectorRunner`; emit evidence pointers, not raw
  sensitive values.
- **A new policy** — write YAML with a CEL `violation` expression (see
  [policy-authoring.md](policy-authoring.md)); no code needed.
- **A new framework mapping** — add a control to the relevant
  `src/aire/mappings/*.yaml`; the CI ref-integrity test enforces that every
  shipped `framework_ref` resolves.
