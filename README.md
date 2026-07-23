# AIRE — AI Runtime Evidence Engine

AIRE is an **observe-only assurance layer** for AI applications. It records
what an AI system actually did at runtime — prompts, retrieved context, tool
calls, memory operations, model responses — as **tamper-evident evidence**,
evaluates that evidence against organizational policies, and produces
**audit reports whose findings cite named governance controls** (EU AI Act,
ISO/IEC 42001, NIST AI RMF, OWASP LLM Top 10).

It answers one question, the way an auditor asks it:

> *If an auditor asked how this AI system behaved yesterday, what evidence
> could we provide?*

Every finding is **`finding → evidence pointer → framework citation`** — a
detected condition, the append-only hash-chained event(s) that prove it, and
the control it maps to. AIRE never asserts "this system is compliant"; it
gives auditors verifiable evidence and leaves judgment to them.

> **Status:** v1 feature-complete and tested (178 tests). Apache-2.0.
> Not yet published to a package index.

---

## Why AIRE

The AI-assurance space splits into tools that watch (LLM observability:
traces and dashboards), tools that block (guardrails and gateways:
enforcement), and platforms that document (GRC: policy registers and
process). None of them produce **tamper-evident runtime evidence, evaluated
against policy, with findings mapped to framework controls** — the artifact a
real audit needs. AIRE is that missing piece, and it is open source.

What makes it defensible under scrutiny:

- **Observe-only and fail-open** — the sensor never transforms, blocks, or
  breaks the host application. A sensor failure is recorded as evidence, not
  raised as an exception. (This also removes the determinism problem that
  plagues enforcement middleware: nothing is transformed, only recorded.)
- **Tamper-evident by construction** — the evidence log is append-only
  (database triggers) and hash-chained (each event carries the previous
  event's SHA-256). `aire verify` detects and localizes any post-hoc edit,
  insertion, deletion, or reordering.
- **Policies are data, in a real language** — an auditor-friendly YAML
  surface compiled to [CEL](https://cel.dev/) (a sandboxed, industry-standard
  expression language), never a homegrown DSL.
- **One deep control, done properly** — memory retention & deletion
  verification: it cross-examines what the app *claimed* (the recorded
  deletion events) against what is *actually stored* (the memory database,
  opened read-only) to answer "was the deleted data really removed?".
- **Measured, not asserted** — detectors are evaluated against public
  benchmarks (AgentDojo, AgentLeak) with reproducible numbers in
  [`evals/RESULTS.md`](evals/RESULTS.md).

---

## How it works

```
   Your AI app (Anthropic SDK + LangGraph memory, or your own stack)
        │  instrumented — observe-only, fail-open
        ▼
   Collectors ──────────────►  AuditEvent  (Pydantic; OTel-GenAI-aligned fields)
        │                          │
        │                          ▼
        │                   Evidence store  (SQLite WAL · append-only · SHA-256 hash chain)
        │                          │
        │        ┌─────────────────┼──────────────────┐
        │        ▼                 ▼                  ▼
        │   Policy engine     Detectors          Deep memory control
        │   (YAML → CEL)   (PII · injection ·   (retention / deletion
        │        │          completeness)        verification, read-only)
        │        └─────────────────┬──────────────────┘
        │                          ▼
        │              findings + policy results
        │              (appended to the SAME hash chain — evidence too)
        ▼                          ▼
   host app unaffected      Report generator  →  JSON · Markdown · HTML
                            finding → evidence pointer → framework citation
```

Policy evaluation and detection run **out-of-band** over the stored evidence,
never inline in the request path — so detection cost is a measurable audit
metric, not a latency tax on the host application.

---

## Quickstart

```bash
# Install (core + the collector/detector extras you need)
python -m venv .venv && source .venv/bin/activate
pip install -e ".[anthropic,langgraph,pii]"
python -m spacy download en_core_web_sm   # for the PII detector
```

**1. Instrument your app** (observe-only — it wraps your client and returns it):

```python
import anthropic
from aire.collectors import session
from aire.collectors.anthropic_sdk import instrument
from aire.store import EvidenceStore

store = EvidenceStore("evidence.db")
client = instrument(anthropic.Anthropic(), store=store, app="support-agent")

with session("customer-42"):          # attribute events to a session
    client.messages.create(...)       # use the client exactly as before
```

On OpenAI or Azure OpenAI instead, swap the import for
`aire.collectors.openai_sdk.instrument` and call `client.chat.completions
.create(...)` — same pattern, same evidence schema (detectors and policies
don't change; only the collector is provider-specific). Pass
`system="azure.ai.openai"` when instrumenting an `AzureOpenAI` client.

For LangGraph memory, wrap the checkpointer with
`aire.collectors.langgraph.InstrumentedSaver` — see
[`examples/support_agent/`](examples/support_agent/) for a full instrumented
FastAPI app.

**2. Evaluate policies and run detectors** (out-of-band, over the evidence):

```bash
aire evaluate evidence.db --builtin           # organizational policies → results
aire detect   evidence.db --memory-db memory.db --retention-days 90
```

**3. Generate an audit report and verify integrity:**

```bash
aire report evidence.db --out audit.html      # JSON / Markdown / HTML
aire verify evidence.db                        # confirm the chain is intact
```

A sample HTML report is in [`docs/sample-report.html`](docs/sample-report.html).

**4. Or browse it in the local dashboard** (read-only, localhost only):

```bash
pip install -e ".[dashboard,pii,langgraph]"
aire dashboard --demo          # a synthetic populated audit, in 60 seconds
aire dashboard evidence.db     # or your own store
```

The dashboard is an auditor-facing viewer over the same evidence — overview →
findings triage → session timeline → event drill-down (with hashes). It never
writes to the store, binds `127.0.0.1`, and serves no scripts or external
resources. See [`docs/dashboard.md`](docs/dashboard.md).

---

## What it detects (v1)

| Control | What it checks |
|---|---|
| **Memory retention & deletion** (deep control) | Was a recorded deletion actually honored in the memory store? Retention age exceeded? PII persisted in memory? Cross-session memory reads? |
| **PII** | Personal data in prompts, responses, tool results, retrieved context, and memory — via [Microsoft Presidio](https://microsoft.github.io/presidio/). |
| **Prompt injection** | Direct and indirect (tool-result / retrieved-context) injection via transparent, weighted heuristics. |
| **Audit-log completeness** | Chain breaks, dropped-event gaps, unmatched request/response pairs. |
| **Policy engine** | Any organizational rule expressible in CEL over an event — tool allowlists, model inventories, human-review requirements, session attribution, and more. |

Findings map to controls in
[`docs/framework-mappings.md`](docs/framework-mappings.md) (generated from the
mapping source of truth via `aire mappings`).

---

## Security

AIRE is built for regulated, industrial use; security is a design constraint
at every layer, not a feature. In brief: evidence files are owner-only
(0600), findings record entity types and offsets but **never raw PII**,
external stores are inspected strictly read-only, all scanned content is
treated as adversarial (bounded scans, ReDoS-safe patterns, no dynamic code
evaluation), and reports are self-contained with autoescaped output. The full
threat model is in [`SECURITY.md`](SECURITY.md).

---

## Evaluation

Detectors are measured against public benchmarks by an offline replay harness
(no LLM calls; deterministic and free to reproduce) — see
[`evals/`](evals/) and [`evals/RESULTS.md`](evals/RESULTS.md):

- **AgentDojo** (arXiv 2406.13352) — prompt-injection detection.
- **AgentLeak** (arXiv 2602.11510) — internal-channel (inter-agent / shared
  memory) PII leakage, the channels an output-only audit structurally cannot
  see.

---

## Documentation

- [Architecture](docs/architecture.md) — modules, event flow, the hash chain.
- [Pilot guide](docs/pilot-guide.md) — running AIRE on a real Anthropic + LangGraph app.
- [Dashboard](docs/dashboard.md) — the local read-only audit viewer.
- [Policy authoring](docs/policy-authoring.md) — writing YAML/CEL policies.
- [Framework mappings](docs/framework-mappings.md) — control citations.
- [Security](SECURITY.md) — threat model and reporting.
- [Contributing](CONTRIBUTING.md) — dev setup and adding controls.

## Roadmap (out of v1)

Enforcement mode (blocking/redaction), governance dashboards, additional
collectors (LiteLLM, Google Gemini), OTLP export, PostgreSQL storage, more
deep controls, and SIEM integration.

## License

Apache-2.0 — see [`LICENSE`](LICENSE).
