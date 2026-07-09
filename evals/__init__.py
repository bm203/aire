"""AIRE evaluation harness (research; not shipped in the aire wheel).

Measures AIRE's detectors against public benchmarks — AgentDojo (prompt
injection, arXiv 2406.13352) and AgentLeak (multi-agent PII leakage, arXiv
2602.11510) — plus evidence-store overhead and report-generation time.

Design principles carried from the tool itself:

- **No invented numbers.** Every figure in RESULTS.md is computed here from a
  named corpus; the methodology is in the docstrings and the report header.
- **Replay, not live LLM calls.** Benchmarks are fed through AIRE's pipeline
  as recorded events, so runs are deterministic, free, and reproducible.
- **Security.** Benchmark data is untrusted third-party input (and contains
  PII by design): it is parsed as data only (never eval'd), string sizes are
  bounded by the detectors' own limits, and the generated report contains
  only aggregate counts and rates — never raw PII or benchmark payloads.
"""
