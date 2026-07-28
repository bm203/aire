# Dependency management & supply-chain security

AIRE is an assurance tool for regulated, industrial use: a compromised or
unstable dependency undermines the trust the tool exists to provide. (AIRE
itself flags OWASP LLM03 "Supply Chain" for the systems it audits; it holds
itself to the same bar.) This document describes how dependencies are
specified, locked, updated, and scanned.

## Strategy: two layers

| Layer | File | Version style | Audience |
|---|---|---|---|
| **Abstract specification** | `pyproject.toml` `[project]` + `[project.optional-dependencies]` | Flexible lower-bound ranges (`>=`) | People who `pip install aire`: they resolve against their own environment. |
| **Concrete lock** | `requirements.lock` | Exact pins with cryptographic hashes | Reproducible, auditable installs: CI, and any deployment that wants a byte-for-byte environment. |

`pyproject.toml` is the single source of truth. `requirements.lock` is
**generated from it**: never hand-edited. This is the standard library
pattern: keep ranges loose for consumers so AIRE doesn't over-constrain their
environments, and pin+hash a lockfile for the builds that must be
reproducible and verifiable.

## Lockfile generation

The lock is compiled from `pyproject.toml` (all extras) with hashes:

```bash
pip install -e ".[dev]"          # brings pip-tools
pip-compile --all-extras --generate-hashes --strip-extras --allow-unsafe \
  --output-file=requirements.lock pyproject.toml
```

- `--all-extras`: locks every optional group (anthropic, langgraph, pii,
  examples, eval, dev) so a single lock covers the full CI/dev surface.
- `--generate-hashes`: records a SHA-256 for every artifact, so installs are
  verified against tampering (`pip --require-hashes` refuses anything whose
  hash doesn't match).
- `--strip-extras`: emits plain pinned requirements (no extras markers),
  suitable for `pip install --require-hashes`.
- `--allow-unsafe`: also pins the build/installer packages (`pip`,
  `setuptools`, `wheel`). Without it, `pip install --require-hashes` can be
  rejected because those packages are unpinned; pinning them makes the
  environment fully reproducible and lets `pip-audit` catch a vulnerable
  installer (this is now the recommended pip-tools default).

> **Flags must match exactly.** CI recompiles the lock and fails on any diff
> (see below), so the generation command and the CI check must use the *same*
> flag set: including `--allow-unsafe`.

Regenerate the lock whenever `pyproject.toml`'s dependencies change, and
commit `requirements.lock` alongside that change.

> **Residual, documented:** the PII detector needs a spaCy model
> (`en_core_web_sm`), which is fetched by spaCy's own downloader, not pip: 
> so it is **not** covered by `requirements.lock`'s hashes. For a fully
> hash-verified environment, install the model from its pinned wheel URL with
> a hash instead of `spacy download` (see spaCy's model release page). CI
> currently uses `spacy download`; this is the one un-hashed fetch and is
> called out here rather than hidden.

## Update & cooldown policy

New releases are **not** adopted immediately. A dependency version must be at
least **14 days old** before it is pinned into `requirements.lock`. This
"cooldown" defends against the two most common supply-chain failure modes:

- a malicious release published and then yanked within hours/days, and
- a fresh release carrying a regression or breaking change not yet caught.

The cooldown is enforced in the update workflow, not left as a manual rule:

- **Automated:** [`.github/dependabot.yml`](../.github/dependabot.yml)
  configures Dependabot for the `pip` ecosystem with a 14-day cooldown, so
  update PRs are only opened for versions that have already passed the
  quarantine window.
- **Manual bumps:** when updating by hand, only pin a version released ≥ 14
  days ago, then regenerate the lock (above) and let CI verify it.

> Dependabot's `cooldown` schema has evolved; verify the block in
> `dependabot.yml` against the current
> [Dependabot configuration reference](https://docs.github.com/code-security/dependabot/dependabot-version-updates/configuration-options-for-the-dependabot.yml-file)
> before relying on it.

## CI security checks

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) enforces the chain
on every push and pull request:

1. **Hash-verified install**: CI installs from `requirements.lock` with
   `pip install --require-hashes -r requirements.lock`, so the tested
   environment is exactly the pinned, hashed one. Any artifact whose hash
   doesn't match aborts the build.
2. **Vulnerability scan**: `pip-audit` checks the locked tree against the
   PyPI Advisory / OSV databases. A pinned package with a known CVE fails the
   build, which is the intended signal to update (after cooldown) or to record
   an explicit, justified exception.
3. Lint (`ruff`) and the full test suite (`pytest`) then run against that
   verified environment.

Handling a `pip-audit` failure: prefer bumping the affected package to a
patched version (respecting the cooldown). If no fix exists yet, an advisory
may be temporarily ignored with `pip-audit --ignore-vuln <ID>` **plus a
comment recording the advisory, the reason, and a review date**: never a
silent suppression.

## Validating the setup

To confirm the supply-chain controls are working:

```bash
# 1. The lock is in sync with pyproject (no drift). This re-compiles and
#    should produce NO changes to requirements.lock:
pip-compile --all-extras --generate-hashes --strip-extras --allow-unsafe \
  --output-file=requirements.lock pyproject.toml
git diff --exit-code requirements.lock        # exit 0 = in sync

# 2. A hash-verified install succeeds from a clean environment:
python -m venv /tmp/aire-verify && . /tmp/aire-verify/bin/activate
pip install --require-hashes -r requirements.lock
pip install -e . --no-deps                     # the local package, deps already locked

# 3. No known vulnerabilities in the locked tree (skips the local package):
pip-audit --skip-editable

# 4. The suite still passes against the locked environment:
python -m spacy download en_core_web_sm
ruff check . && pytest -q
```

Step 1 is the important invariant: **`requirements.lock` must always be
regenerable from `pyproject.toml` with no diff.** A non-empty diff means the
lock is stale: someone changed a dependency without recompiling.
