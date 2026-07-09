# AIRE evaluation harness

Measures AIRE's detectors against public benchmarks and reports overhead.
All figures in [`RESULTS.md`](RESULTS.md) are computed here — none are
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

## Notes

- AgentLeak trace data is **not vendored** into this repo (it contains PII by
  design). The committed fixture is synthetic with fake PII, for CI only.
- `RESULTS.md` contains only aggregate counts and rates — never benchmark
  payloads or PII.
