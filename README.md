# AIRE — AI Runtime Evidence Engine

AIRE sits between enterprise AI applications and foundation models, continuously
collecting audit evidence, evaluating organizational policies, and generating
reports mapped to governance frameworks such as the EU AI Act, ISO/IEC 42001,
and the NIST AI Risk Management Framework.

## Status

Early design phase. Nothing to run yet.

## Planned v1 scope

- **Runtime audit sensor** — observe-only interceptor for prompts, retrieved
  context, memory operations, tool calls, and model responses. Passive by
  design: the sensor can never break the host application.
- **Policy engine** — auditor-friendly YAML policy surface compiled to an
  industry-standard engine (OPA/Rego or CEL) underneath; configurable
  organizational controls, not hardcoded rules.
- **Evidence store** — structured, append-only, hash-chained event log
  (tamper-evident audit evidence).
- **Audit report generator** — findings with evidence pointers and framework
  citations (EU AI Act / ISO-IEC 42001 / NIST AI RMF / OWASP), not a
  compliance checklist.
- **One deep control** — memory retention & data-persistence verification for
  a single concrete memory stack.

Enforcement mode (blocking/redaction), additional controls, and dashboards are
roadmap items, deliberately out of v1 scope.

## Background

The design grew out of unpublished research on exposure control for
multi-agent LLM systems. The scope was repositioned from enforcement
middleware to an audit-evidence engine; a systems paper with measured
results is planned once v1 is built and evaluated.
