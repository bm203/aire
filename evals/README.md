# AIRE evaluation harness

Measures AIRE's detectors against public benchmarks and reports overhead.
All figures in [`RESULTS.md`](RESULTS.md) are computed here: none are
hand-written. Replays are offline (no LLM calls), so runs are deterministic
and free to reproduce.

## Run

```bash
pip install -e ".[eval,pii]"
python -m spacy download en_core_web_sm

# AgentDojo runs from the pip package; AgentLeak uses a synthetic CI fixture
python -m evals.run

# For real AgentLeak numbers, clone the dataset (MIT-licensed) and point at it:
git clone https://github.com/Privatris/AgentLeak /tmp/AgentLeak
python -m evals.run --agentleak-data /tmp/AgentLeak/agentleak_data/datasets
```

## What is measured

| Benchmark | Corpus | Metric |
|---|---|---|
| **AgentDojo** (arXiv 2406.13352) | `important_instructions` attack rendered per injection-task goal (positives) vs. benign injection-vector texts + user prompts (negatives), replayed as `tool.result` events | prompt-injection precision / recall / F1 / FP-rate, detector latency |
| **AgentLeak** (arXiv 2602.11510) | internal-channel traces (inter-agent messages, shared memory) replayed as evidence events; ground truth = each channel's `pii_exposed` | internal-channel PII recall, per channel kind; contrast vs. 0% output-only-auditor coverage |
| **Overhead** | synthetic | evidence-store append latency, report build time |
| **Industrial IT/OT scenario** (`evals/industrial/`) | deterministic, ground-truth-labeled multi-agent maintenance/operations workflow: clearance-tiered agents with four planted internal-channel conditions (indirect injection via a maintenance-log tool result, PII in shared memory, cross-clearance memory read, unhonored data-erasure) | per-condition detection coverage, event-level precision/recall/F1/FP, contrast vs. 0% output-only-auditor coverage |

Run the industrial scenario (needs the `pii` + `langgraph` extras):

```bash
python -m evals.industrial.run          # writes evals/industrial/RESULTS.md
```

It is deterministic (scripted events with known ground truth: no LLM calls),
so the true/false-positive numbers are reproducible. All data is synthetic
(no personal data, no secrets, no company names); the PII scanner is tuned to
a real personal-data entity set (dropping the DATE_TIME/ORGANIZATION/URL noise
Presidio flags by default).

## Notes

- AgentLeak trace data is **not vendored** into this repo (it contains PII by
  design). The committed fixture is synthetic with fake PII, for CI only.
- `RESULTS.md` contains only aggregate counts and rates, never benchmark
  payloads or PII.
