# Pilot guide: running AIRE on a real Anthropic + LangGraph app

This is the operator's guide for a **pilot**: putting AIRE onto a real AI
application (built on the Anthropic SDK with LangGraph memory), capturing a few
days of genuine activity, and producing an audit report the app's owners can
read. It complements the [README quickstart](../README.md#quickstart): the
quickstart shows the mechanics; this guide is about running them *on someone
else's production/staging app*, and the assurances their security team will
ask for first.

> **What a pilot proves.** Not "the app is compliant." It proves AIRE can sit
> in front of a real system and produce *verifiable evidence*: findings that
> each point at a hash-chained event and a named framework control, with **no
> impact on the host application**. That evidence is the pilot's deliverable.

## Before you start: the assurances (share these first)

An IT/OT security team will ask these before you touch their app. The answers
are design properties, not promises:

- **It cannot break the app.** The sensor is **observe-only and fail-open**:
  it wraps the client and returns it unchanged; it never blocks, transforms, or
  delays a call. If the sensor itself errors, that becomes a recorded
  finding, never an exception in the host. (See [SECURITY.md](../SECURITY.md).)
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

## Step 0: Install (in the app's environment)

```bash
pip install "aire[anthropic,langgraph,pii]"
python -m spacy download en_core_web_sm   # for the PII detector
```

`anthropic` + `langgraph` are the collectors; `pii` adds the Presidio detector.
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

Run the app normally against real traffic for the pilot window (a few hours to
a few days). AIRE records prompts, retrieved context, tool calls, memory
operations, and model responses into `evidence.db` as they happen. There is
nothing to babysit; the app behaves identically whether AIRE is there or not.

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
aire verify evidence.db                       # confirm the chain is intact
aire report evidence.db --out audit.html      # the hand-off artifact (also md/json)
aire dashboard evidence.db                     # or browse it interactively (localhost)
```

Walk the app owners through it the way an auditor would: overall risk and the
**intact chain** first (the evidence is trustworthy), then each finding →
its **evidence pointer** (the event id + SHA-256) → its **framework citation**.
`aire verify` is the thing that makes it defensible: it proves no one edited
the evidence after the fact.

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
