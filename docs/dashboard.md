# Dashboard

A local, **read-only** web view over an evidence store — the auditor-facing
surface for the findings, risk, framework citations, and event timeline that
AIRE records. It adds no detection logic; it renders what `aire evaluate` /
`aire detect` already produced.

## Try it in 60 seconds

```bash
pip install -e ".[dashboard,pii,langgraph]"
python -m spacy download en_core_web_sm     # for the demo's PII detector
aire dashboard --demo
```

`--demo` builds a **synthetic** industrial IT/OT audit (no API key, no external
data, no company names), runs the real pipeline over it, and serves it at
<http://127.0.0.1:8787>. You'll see a critical-risk audit with findings across
every detector — prompt injection, PII in memory, an unhonored data erasure,
and policy violations — each linking to its evidence event and framework
citation.

## On your own evidence

```bash
# 1. produce findings (writes to the store's append-only chain)
aire evaluate evidence.db --builtin
aire detect   evidence.db --memory-db memory.db --retention-days 90
# 2. view them
aire dashboard evidence.db
```

Pages: **overview** (chain status, overall risk, sessions, a link to the
findings triage) → **/findings** (every finding across sessions, filter by
severity) → **/session?id=…** (a session's findings + raw event timeline) →
**/event?id=…** (one event: type, timestamp, SHA-256 hash + prev-hash,
payload). `/api/report.json` exports the full `AuditReport`.

Options: `--port` (default 8787), `--title`, `--host` (default `127.0.0.1`).

## Security

The dashboard carries the same posture as the rest of AIRE and is built for
**local single-user** use:

- **Read-only** — the evidence store is opened OS-level read-only (`mode=ro`);
  the dashboard cannot write to it. There are no POST routes.
- **Localhost only, no authentication** — it binds `127.0.0.1` by default and
  has no login. **Do not expose it publicly.** If you must reach it remotely,
  put it behind an authenticating reverse proxy; binding a non-localhost
  `--host` prints a warning.
- **No scripts, no external resources** — pages use a same-origin stylesheet
  and nothing else, enforced by a strict Content-Security-Policy with no
  `script-src` (scripts can never run) and `default-src 'none'`. It renders
  identically air-gapped and never phones home.
- **Untrusted content is escaped and bounded** — event payloads contain the
  actual prompts and any personal data (the evidence); they are HTML-escaped
  and size-capped in the UI. This data stays on your machine — the same
  exposure as opening the SQLite file locally.

See [SECURITY.md](../SECURITY.md) for the full threat model.
