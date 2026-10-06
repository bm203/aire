# Security

AIRE is built for industrial/regulated environments; security is a design
constraint at every level, not a feature.

## Design commitments

- **Observe-only, fail-open sensor.** AIRE never transforms, blocks, or
  redacts host-application traffic. Evidence is written by a background
  thread from a bounded queue, so the host never waits on the store. Collector
  failures and queue overflow are swallowed, counted, and surfaced as
  `sensor.dropped` evidence, never as exceptions in the host app.
- **Tamper-evident evidence, within a stated limit.** The evidence log is
  append-only (enforced by database triggers) and hash-chained (each event
  carries the previous event's SHA-256). `aire verify` detects and localizes
  edits, insertions, deletions, and reordering that leave the chain
  inconsistent. The chain uses no secret: someone with write access to the
  store can rewrite events and recompute every later hash. That rewrite is
  detected only against a chain head recorded outside their reach: a head
  passed to `aire verify --expect-head <seq>:<hash>` (every report carries it),
  or checkpoints from `aire checkpoint`, Ed25519-signed with a key the writer
  cannot read and/or sent to a witness the writer does not control, checked
  with `aire verify --checkpoints FILE --pubkey KEY.pub --max-gap N`.
- **Evidence is treated as sensitive data.** The store contains prompts,
  model outputs, memory contents, and possibly personal data. Database files
  (including WAL/SHM sidecars) are created with owner-only permissions
  (0600). Findings record entity types, scores, and offsets, never copies
  of the matched values; the evidence pointer identifies the source event.
- **Never touch the host's data.** Inspection of external stores (e.g. the
  LangGraph checkpointer database) uses strictly read-only connections
  (`mode=ro` SQLite URI); a write attempt fails at the SQLite level.
- **All scanned content is untrusted.** Prompts, tool results, and retrieved
  context can be adversarial: scan sizes are bounded (DoS), detection
  patterns are precompiled without nested quantifiers (ReDoS), SQL is
  parameterized throughout, and there is no dynamic code evaluation: 
  policy expressions run in CEL, a sandboxed expression interpreter with no
  I/O, imports, or side effects.
- **Crash-safe controls.** A crashing detector becomes a finding ("this
  control did not run: coverage is incomplete"), because silent gaps in an
  audit are worse than reported ones.
- **Supply-chain hygiene.** Dependencies are pinned and hash-locked
  (`requirements.lock`), scanned for known vulnerabilities in CI
  (`pip-audit`), and held to a 14-day maturity cooldown before adoption. See
  [dependency-management.md](docs/dependency-management.md).
- **The dashboard is a local read-only viewer.** It opens the evidence store
  read-only (cannot write), binds `127.0.0.1` with no authentication, serves
  no scripts or external resources (strict CSP, no `script-src`), and
  size-bounds/escapes untrusted payloads. It is single-user-local by design: 
  do not expose it publicly without an authenticating reverse proxy. See
  [dashboard.md](docs/dashboard.md).

## Threat model (v1 scope)

| Threat | Mitigation |
|---|---|
| Accidental or naive edits to evidence | Append-only triggers stop mutation through the normal write path; `aire verify` localizes any edit that breaks the chain |
| Deliberate rewrite by someone with write access (edit + recompute the chain) | **Not detected by the chain alone.** Detected up to the latest checkpoint: signed checkpoints (key held where the writer cannot read it) and/or checkpoints delivered to a witness the writer does not control; or a head recorded by hand and passed to `--expect-head` |
| Forging or editing checkpoints | Ed25519 signatures over a canonical statement; `--pubkey` requires a valid signature from a known key on every checkpoint |
| Replaying a checkpoint from another store | Each store has an immutable id; every checkpoint names it |
| Deleting recent checkpoints to rewrite what they covered | `--max-gap N` fails when more than N events follow the latest checkpoint; a witness keeps its own copy |
| Signing key readable by the writer | Not mitigated: such a key lets the writer forge checkpoints. Keep it on another user, host, or in an HSM/KMS; prefer a witness the writer does not control |
| Removal of events after the last checkpoint | Not detected until the next checkpoint; the checkpoint interval is the exposure window |
| Compromised host at recording time (fabricated or suppressed events) | Out of scope: evidence is only as trustworthy as the host that recorded it. Imported coding-agent logs carry the same limit for the log's source |
| Adversarial content in prompts/tool results (injection, DoS payloads) | Bounded scans, ReDoS-safe patterns, detection out-of-band of the request path |
| AIRE breaking or degrading the monitored app | Fail-open sensor, no inline transformation, host errors propagate untouched; writes on a background thread from a bounded queue, overflow counted as `sensor.dropped` (measured host cost in `evals/RESULTS.md`) |
| Evidence lost on a hard crash | Events still in the background queue (typically milliseconds' worth) are lost if the process is killed hard; normal shutdown flushes them. Use `background=False` where losing any event is worse than adding write latency to the host |
| AIRE corrupting the host's memory store during audit | Read-only connections, enforced by SQLite |
| Evidence leaking to other local users | 0600 file permissions on DB + sidecars |
| PII amplification through findings | Findings carry types/offsets/pointers, not values |
| Dashboard exposing evidence over the network | Read-only store open, localhost-only bind (warns otherwise), strict CSP, no scripts/external resources |
| Malicious or vulnerable dependency | Hash-pinned lockfile, `pip-audit` in CI, 14-day adoption cooldown |

Out of scope in v1 (roadmap): at-rest encryption of the evidence store,
remote/append-to-remote evidence sinks, HSM/KMS-held checkpoint keys,
trusted timestamps for checkpoints (RFC 3161), multi-user access control.

## Reporting a vulnerability

Please open a GitHub security advisory (preferred) or an issue marked
`security` without exploit details, and we will follow up privately.
