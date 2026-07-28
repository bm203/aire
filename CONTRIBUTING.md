# Contributing to AIRE

Thanks for your interest. AIRE is an AI-assurance tool built for regulated,
industrial use: contributions are held to that bar: correctness, security,
and tests are not optional.

## Development setup

AIRE targets Python 3.12+.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[anthropic,langgraph,pii,eval,dev]"
python -m spacy download en_core_web_sm   # for the PII detector / its tests
```

Run the checks before every commit:

```bash
pytest          # full suite
ruff check .    # lint
```

Both must be clean.

### Changing dependencies

`pyproject.toml` holds flexible ranges; `requirements.lock` is the hash-pinned
lockfile CI installs from. If you change a dependency, **regenerate the lock**
in the same PR and respect the 14-day adoption cooldown:

```bash
pip-compile --all-extras --generate-hashes --strip-extras \
  --output-file=requirements.lock pyproject.toml
```

CI verifies the lock is in sync and runs `pip-audit` against it. See
[docs/dependency-management.md](docs/dependency-management.md) for the full
strategy, cooldown policy, and validation steps. Tests that require an optional dependency skip gracefully
when it is absent, so the core suite runs without the extras, but add the
extras above when working on collectors, the PII detector, or the eval harness.

## Optional-dependency layout

The core install carries no heavy dependencies. Feature areas live behind
extras so a deployment only installs what it uses:

| Extra | Enables |
|---|---|
| `anthropic` | The Anthropic SDK collector |
| `langgraph` | The LangGraph checkpointer collector + the deep memory control |
| `pii` | The Presidio-backed PII detector (needs a spaCy model) |
| `examples` | The instrumented FastAPI example app |
| `eval` | The AgentDojo/AgentLeak evaluation harness |
| `dev` | pytest + ruff |

## Adding a control

- **A detector**: implement `Detector.inspect(events, store) -> list[Finding]`
  in `src/aire/detectors/`. Emit **evidence pointers** (source event ids +
  hashes), never copies of raw sensitive values. Add positive *and* negative
  test cases. Register it in `aire.cli`'s `detect` command.
- **A policy**: no code: write YAML with a CEL `violation` expression (see
  [docs/policy-authoring.md](docs/policy-authoring.md)).
- **A collector**: wrap the host SDK/framework and call `Sensor.record()`.
  It **must be fail-open**: a bug in your collector must never raise into the
  host application. Add a fault-injection test proving it.
- **A framework mapping**: add the control to the relevant
  `src/aire/mappings/*.yaml`. The CI ref-integrity test enforces that every
  `framework_ref` shipped in a policy or detector resolves. Control titles
  must be verified against the published source; do not paste proprietary
  standard text (titles only for ISO).

## Security expectations

Every change is reviewed against the commitments in
[SECURITY.md](SECURITY.md). In particular:

- Treat all scanned content (prompts, tool results, retrieved data) as
  **untrusted and possibly adversarial**: bound scan sizes, keep regexes
  ReDoS-safe (no nested quantifiers), parameterize all SQL, and never
  `eval`/`exec` model- or config-supplied strings.
- Inspect external stores (e.g. a memory database) **read-only**.
- Findings, reports, and any generated artifact carry entity types and
  counts: **never raw PII or secrets**.
- If you find a vulnerability, please report it privately (see SECURITY.md);
  do not open a public issue with exploit details.

## Documentation

Public docs (`README.md`, `docs/`, `SECURITY.md`) are part of the product.
`docs/framework-mappings.md` is **generated** from `src/aire/mappings/*.yaml`
via `aire mappings > docs/framework-mappings.md`: edit the YAML, not the
generated file.

## Commit and PR conventions

Keep commits focused and their messages descriptive (what changed and why).
Ensure `pytest` and `ruff check .` pass. New behavior needs tests; new
public-facing behavior needs a docs update in the same PR.

## License

By contributing you agree that your contributions are licensed under the
project's Apache-2.0 license.
