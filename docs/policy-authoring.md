# Policy authoring

AIRE policies are YAML. Each policy names a condition — written in
[CEL](https://cel.dev/) (Common Expression Language, a sandboxed,
industry-standard expression language) — that, when true for an audit event,
constitutes a violation. The YAML is the auditor-facing surface; CEL is the
engine underneath. AIRE never uses a homegrown rule language.

## Anatomy of a policy

```yaml
policies:
  - id: TOOL_ALLOWLIST                 # UPPER_SNAKE, 3–64 chars
    description: Agents may only invoke tools on the approved allowlist.
    severity: high                     # info | low | medium | high | critical
    applies_to: [tool.call]            # event types this policy runs against
    params:                            # data the expression reads (keep values here)
      allowed_tools: ["lookup_order"]
    violation: '!(payload["gen_ai.tool.name"] in params.allowed_tools)'
    verdict_on_violation: fail         # fail (default) | warn
    framework_refs:                    # keys into the framework mappings
      - "OWASP-LLM:LLM06"
      - "EU-AI-ACT:Art.14"
      - "NIST-AI-RMF:MANAGE-3.1"
```

A policy file has a top-level `policies:` list. A directory is loaded as every
`*.yaml`/`*.yml` file it contains (sorted). Duplicate ids are rejected, and
every validation error names the file, policy, and field.

## The three variables

A `violation` expression evaluates against three variables:

| Variable | Contents |
|---|---|
| `event` | Envelope fields: `event_type`, `session_id`, `trace_id`, `app`, `ts`. |
| `payload` | The event's payload map (e.g. `payload["gen_ai.request.model"]`). |
| `params` | This policy's own `params` block — put allowlists, limits, and thresholds here rather than hard-coding them in the expression. |

The expression must evaluate to a boolean. **True means violated.** If the
expression cannot be evaluated against an event (for example, a payload key is
missing), the result is surfaced as an `error` verdict — never hidden — so an
auditor can see where coverage has gaps.

Payload field names follow the OpenTelemetry GenAI conventions where they
exist (`gen_ai.request.model`, `gen_ai.tool.name`, `gen_ai.usage.*`). Inspect
a stored event's payload to see exactly what a given event type carries.

## Examples

```yaml
# Only approved models may be called
violation: '!(payload["gen_ai.request.model"] in params.allowed_models)'
applies_to: [llm.request]

# High-impact tools require a recorded human-approval marker
violation: >-
  payload["gen_ai.tool.name"] in params.review_required_tools
  && !("human_approved" in payload)
applies_to: [tool.call]

# Every interaction must be attributed to a session (warn, not fail)
violation: 'event.session_id == "unattributed"'
verdict_on_violation: warn
applies_to: [llm.request, llm.response, tool.call, memory.write]
```

The builtin starter pack
([`src/aire/policy/builtin/starter_pack.yaml`](../src/aire/policy/builtin/starter_pack.yaml))
ships these as templates — copy them and adapt the `params` to your
organization.

## Running policies

```bash
aire evaluate evidence.db --policies my_policies/     # your policy directory
aire evaluate evidence.db --builtin                   # AIRE's starter pack
aire evaluate evidence.db --builtin --session cust-42 # scope to one session
```

The engine runs out-of-band over the stored evidence. Fail/warn/error results
are appended to the hash chain as `policy.result` events, each carrying an
**evidence pointer** (the source event's id and hash). Pass results are
aggregated into a single per-run summary event — coverage proof without log
noise. Re-running is idempotent: a result already on the chain is never
recorded twice.

## Framework references

Each `framework_ref` is a `<FRAMEWORK>:<control-id>` key resolved against the
mapping files in `src/aire/mappings/`. Reports turn these into full citations
(control title + link). A CI test asserts every ref shipped with AIRE
resolves; if you add a ref to a control that isn't mapped yet, add it to the
relevant mapping YAML — see
[framework-mappings.md](framework-mappings.md) for the current set.

## Notes on CEL and safety

CEL is evaluated by an in-process interpreter with no I/O, imports, or side
effects — an expression cannot read files, make network calls, or execute
arbitrary code. This is deliberate: policies are configuration authored by
governance teams, and the evaluation surface must not become a code-execution
vector. Expression compile errors are reported at load time with the offending
policy id.
