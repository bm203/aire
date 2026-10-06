# Pilot guide: running AIRE on a real AI application

This is the operator's guide for a **pilot**: putting AIRE onto a real AI
application, capturing genuine activity for an agreed window, and producing an
audit report the app's owners can read. The steps below use an app built on the
Anthropic SDK with LangGraph memory; the OpenAI / Azure OpenAI collector and the
coding-agent importers (Claude Code, Codex) slot into the same flow. It
complements the [README quickstart](../README.md#quickstart): the quickstart
shows the mechanics; this guide is about running them *on someone else's
production/staging app*, and what their security team will ask first.

Sections: [pilot at a glance](#pilot-at-a-glance) ·
[data flow](#data-flow) · [deployment](#deployment) ·
[data handling](#data-handling) ·
[security assumptions and limitations](#security-assumptions-and-limitations) ·
[success criteria](#success-criteria) · then the steps (0 to 4).

> **What a pilot proves.** Not "the app is compliant." It proves AIRE can sit
> in front of a real system and produce *verifiable evidence*: findings that
> each point at a hash-chained event and a named framework control, with **no
> impact on the host application**. That evidence is the pilot's deliverable.

## Before you start: the assurances (share these first)

An IT/OT security team will ask these before you touch their app. The answers
are design properties, not promises:

- **It cannot break the app.** The sensor is **observe-only and fail-open**:
  it wraps the client and returns it unchanged; it never transforms a call,
  and writes happen on a background thread, so the app's own threads never
  wait on the evidence database. Measured: about 0.03 ms per instrumented call,
  no host wait above 0.2 ms with eight worker processes recording flat out
  (`evals/RESULTS.md`). If recording cannot keep up, events are dropped and
  counted as evidence instead of slowing the app. If the sensor itself errors,
  that becomes a recorded finding, never an exception in the host. (See
  [SECURITY.md](../SECURITY.md).)
- **It never writes to their data.** The app's memory store is inspected
  **strictly read-only** (`mode=ro`); AIRE has its own separate evidence DB.
- **Evidence stays local and owner-only.** The evidence DB and its sidecars are
  created `0600`; reports are `0600`, self-contained, and reference no external
  resources. Nothing phones home. Findings record entity **types and offsets**,
  never raw PII values.
- **No new network exposure.** Analysis runs offline over the stored evidence.
  The optional dashboard binds `127.0.0.1` only and serves no scripts.

Because the evidence contains real prompts and any personal data the app
handled, **treat the evidence DB as sensitive**: it is exactly as sensitive as
the app's own logs. Agree up front where it lives and who can read it.

## Pilot at a glance

- **One AI application**, ideally an agent with LLM calls, retrieval, tool use,
  sensitive data, and (if available) persistent memory.
- **Three assurance questions**, agreed up front, for example:
  1. *Data:* did personal or sensitive data enter or leave the AI workflow
     unexpectedly?
  2. *Tool use:* did the agent invoke tools outside the approved policy?
  3. *Memory:* when deletion was requested, was the data actually removed?
- **One evidence report**: each finding traced to its events, their hashes, the
  policy evaluated, and the governance control it relates to, plus per-control
  coverage (passed / failed / not evaluated / no evidence).
- **A pilot tests evidence utility, not compliance**: does AIRE produce
  evidence the organization's existing tooling cannot easily produce?

## Data flow

```
 AI application process (unchanged)
   │  wrapped SDK client / checkpointer: builds each event on the app's thread,
   │  queues it in memory (never waits on disk)
   ▼
 background writer thread ──► evidence.db (+ -wal, -shm, .lock)    local disk, 0600
                                      │
             offline, on the same host or a copy of the file:
             aire evaluate / aire detect  (append findings to the same chain)
                                      │
             aire report ──► audit.html / .md / .json (0600, self-contained)
             aire dashboard ──► 127.0.0.1 only, read-only
             aire checkpoint ──► customer witness (SIEM via syslog, audit share)
                                 carries store id, sequence number, head hash,
                                 timestamp, optional signature; no content
```

- **Nothing leaves the environment** unless the organization sends it. AIRE
  makes no outbound connections; the only network output is checkpoints, to a
  destination the organization chooses, and they contain hashes, not content.
- The app's own memory store is opened **read-only** for the deletion control.
- Coding-agent pilots skip the wrapper: `aire import-claude-code` /
  `aire import-codex` read session logs the agent already writes locally.

## Deployment

- **Where:** inside the app's existing Python environment (Python 3.12+). No
  new service, port, container, or database server. A dedicated directory for
  the evidence file is enough.
- **Install:** `pip install "aire[...]"` with the extras for the app's stack
  (`anthropic`, `openai`, `langgraph`, `pii`, `signing`, `dashboard`); a
  hash-pinned `requirements.lock` is available for verified installs.
- **Multi-worker servers:** all worker processes can share one evidence file;
  each process gets its own background writer, and writers take a fair file
  lock. Measured with eight processes recording flat out: no host wait above
  0.2 ms, every event written, chain intact (`evals/RESULTS.md`).
- **Shutdown:** normal shutdown flushes queued events. A hard kill (`kill -9`,
  power loss) loses events still queued, typically milliseconds' worth. Pass
  `background=False` to `instrument(...)` where losing any event is worse than
  adding about 2 ms of write latency to the app.
- **Disk:** evidence grows with the size of the prompts, responses, and tool
  output the app produces. Check the file size after the first day and agree a
  ceiling.
- **Removal:** delete the wrapper lines; the app runs exactly as before. The
  evidence file stays until it is deleted under the agreed retention.

## Data handling

- **What is stored:** prompts, retrieved context, tool calls and results,
  memory operations, and model responses, as the app produced them. Findings
  store entity types, offsets, and pointers, never copies of personal data.
- **Sensitivity:** treat the evidence file like the app's own logs, including
  under the organization's data protection rules. Whether the pilot needs a
  data protection review, and on which legal basis evidence is kept, is the
  organization's decision; agree it before step 1.
- **Retention and erasure:** agree a retention period and an end-of-pilot
  action. The evidence log is append-only, so v1 has no per-record erasure:
  erasure means deleting the evidence file (and its sidecars). Plan the pilot
  window and data scope with that in mind.
- **Access:** owner-only file permissions by default; decide who else may read
  the file, the reports, and the dashboard.
- **Language:** the PII detector is tuned for English text. On German text it
  produces many false positives and misses German identifiers (tax ID, social
  security number), as measured on synthetic German business text. Treat PII
  findings on German-language traffic as indicative only.

## Security assumptions and limitations

The full threat model is in [SECURITY.md](../SECURITY.md). For a pilot, the
points that matter:

- **The host is trusted at recording time.** AIRE records what the app did; a
  compromised host can fabricate or suppress events before they are recorded.
- **Integrity has a stated limit.** The hash chain proves internal
  consistency. Detecting a deliberate rewrite needs a head recorded outside the
  writer's reach: checkpoints sent to a witness the app team does not control
  and/or signed with a key the app's user cannot read. Events after the latest
  checkpoint are unprotected until the next one.
- **Imported coding-agent logs** prove nothing changed after import, not that
  the log itself is faithful.
- **Detection is measured, not perfect.** Injection detection is heuristic
  (evaluated on AgentDojo); PII detection depends on language and text type.
  Every result has an evidence pointer so a reviewer can check it.
- **"Passed" in control coverage** means the configured checks evaluated
  recorded events and found no violation. It is not a statement that the
  control is satisfied.
- **Not covered in v1:** enforcement (AIRE never blocks), per-record erasure,
  HSM/KMS-held signing keys, trusted timestamps.

## Success criteria

Agree targets before the pilot starts; each is measurable from the evidence or
the organization's own monitoring:

| Criterion | How it is measured | Suggested target |
|---|---|---|
| Events captured | Events written vs. events counted as dropped (`sensor.dropped` evidence, completeness detector) | 100% written or counted; drops agreed in advance |
| Evidence integrity | `aire verify --checkpoints ... --pubkey ... --max-gap N` against the witness's copy | Passes for the whole window |
| No impact on the app | The app's own latency and error metrics, before vs. during the pilot | No measurable change |
| Policy violations found | Agreed test scenarios (e.g. a disallowed tool call) run during the window | Every scenario detected, with an evidence pointer |
| Controls addressed | Control coverage section of the report, reviewed with the control owners | Each agreed control passed, failed, or explained |
| Memory deletion verified | Deletion control on a planned deletion request (LangGraph apps) | Claim and actual state compared, result evidenced |
| Data stays local | Network configuration review | No outbound traffic from AIRE |
| Evidence utility | Review with the app owners and auditors | At least one finding worth acting on, plus a list of disputed results |

## Step 0: Install (in the app's environment)

```bash
pip install "aire[anthropic,langgraph,pii]"   # or openai instead of anthropic
python -m spacy download en_core_web_sm   # for the PII detector
```

`anthropic` (or `openai`, which also covers Azure OpenAI) + `langgraph` are the
collectors; `pii` adds the Presidio detector.
No API key is needed for analysis: only the app itself already has one.

## Step 1: Instrument the app (≈4 lines)

Find where the app constructs its Anthropic client and its LangGraph
checkpointer, and wrap both. Everything else in the app stays the same.

```python
from aire.collectors import session
from aire.collectors.anthropic_sdk import instrument
from aire.collectors.langgraph import InstrumentedSaver
from aire.store import EvidenceStore

store = EvidenceStore("evidence.db")                       # AIRE's own DB (separate)

# was:  client = anthropic.Anthropic()
client = instrument(anthropic.Anthropic(), store=store, app="pilot-app")

# was:  memory = SqliteSaver(conn)
memory = InstrumentedSaver(SqliteSaver(conn), store=store, app="pilot-app")
```

Then wrap each request in a `session(...)` so events are attributed to a
conversation/thread (use whatever id the app already has: a ticket id, a
thread id):

```python
with session(request_id):        # attribute events to this session
    client.messages.create(...)  # use the client exactly as before
```

That's the whole integration. See
[`examples/support_agent/app.py`](../examples/support_agent/) for a full
working example of this exact wiring.

## Step 2: Let it run

Run the app normally against real traffic for the pilot window. AIRE records
prompts, retrieved context, tool calls, memory operations, and model responses
into `evidence.db` as they happen. Schedule `aire checkpoint` to the agreed
witness (see step 4) from day one. Run the agreed test scenarios during the
window so the success criteria can be checked.

## Step 3: Analyse the evidence (offline, over the store)

When you have a representative window, run the policy engine and detectors.
This appends findings and policy results to the *same* hash chain: they are
evidence too.

```bash
# organizational policies (start with the builtin starter set)
aire evaluate evidence.db --builtin

# detectors: PII + injection + completeness, plus the deep memory control
aire detect evidence.db --memory-db memory.db --retention-days 90
```

`--memory-db` points at the app's LangGraph checkpointer DB (opened read-only)
and enables the retention/deletion control, the one that cross-examines what
the app *claimed* to delete against what is *actually still stored*.
`--retention-days` is the pilot org's stated memory-retention limit.

Tune policies to the org by writing YAML (approved model inventory, tool
allowlist, human-review rules) and passing `-p policies.yaml` alongside or
instead of `--builtin`: see [policy authoring](policy-authoring.md).

## Step 4: Deliver the evidence

```bash
aire verify evidence.db                       # confirm the chain is intact; prints the head
aire report evidence.db --out audit.html      # the hand-off artifact (also md/json)
aire dashboard evidence.db                     # or browse it interactively (localhost)
```

Walk the app owners through it the way an auditor would: overall risk and the
**intact chain** first (the evidence is trustworthy), then each finding →
its **evidence pointer** (the event id + SHA-256) → its **framework citation**.
`aire verify` is what makes it defensible, with one step that matters: **hand
the printed head (`<seq>:<hash>`) to the app owners now** (it is also in the
report). The chain alone proves internal consistency; with the head held by
someone else, `aire verify --expect-head <head>` later proves nobody rewrote
the evidence up to that point, including someone with access to the file.

For a pilot that runs longer than a day, automate this with checkpoints sent
to a system the app team does not control (their SIEM, or a share owned by
security or audit), on a schedule:

```bash
pip install "aire[signing]"
aire keygen /secure/aire-signer            # keep the private key away from the app's user
aire checkpoint evidence.db --sign /secure/aire-signer --sink syslog:siem.internal
# later, by the auditor, with the witness's copy of the checkpoints:
aire verify evidence.db --checkpoints checkpoints.log --pubkey aire-signer.pub --max-gap 1000
```

## What to capture back (the pilot's real output)

The point of the pilot is *feedback*, so record it as you go:

- **False positives / negatives**: anything the org disputes, with the event
  id. (Detector precision on their real data is a headline result.)
- **Integration friction**: anything awkward about steps 1–3 on their stack.
- **Missing controls**: governance questions their org asks that AIRE can't
  yet answer.
- **The real outcome**: did any finding surface something genuinely worth
  fixing? That one sentence is what earns the word "reliable."

Feed these into the issue tracker as a triaged bug/hardening list: that list,
plus one real outcome, is the exit criterion for the pilot.
