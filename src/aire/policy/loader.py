"""Load and validate policy YAML files.

A policy file has a top-level ``policies:`` list; a directory is loaded as
every ``*.yaml`` / ``*.yml`` file it contains, sorted by name. All validation
errors carry the file (and policy id where known) so an auditor can fix the
YAML without reading Python tracebacks.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from aire.policy.models import Policy

_BUILTIN_DIR = Path(__file__).parent / "builtin"


class PolicyLoadError(Exception):
    pass


def load_policies(path: str | Path) -> list[Policy]:
    path = Path(path)
    if path.is_dir():
        files = sorted(p for p in path.iterdir() if p.suffix in (".yaml", ".yml"))
        if not files:
            raise PolicyLoadError(f"{path}: no .yaml/.yml policy files found")
    elif path.is_file():
        files = [path]
    else:
        raise PolicyLoadError(f"{path}: no such file or directory")

    policies: list[Policy] = []
    seen_ids: dict[str, Path] = {}
    for file in files:
        for policy in _load_file(file):
            if policy.id in seen_ids:
                raise PolicyLoadError(
                    f"{file}: duplicate policy id {policy.id!r} "
                    f"(already defined in {seen_ids[policy.id]})"
                )
            seen_ids[policy.id] = file
            policies.append(policy)
    return policies


def builtin_policies() -> list[Policy]:
    """The starter policy pack shipped with AIRE (copy and adapt the params)."""
    return load_policies(_BUILTIN_DIR)


def _load_file(file: Path) -> list[Policy]:
    try:
        data = yaml.safe_load(file.read_text())
    except yaml.YAMLError as exc:
        raise PolicyLoadError(f"{file}: invalid YAML: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("policies"), list):
        raise PolicyLoadError(f"{file}: expected a top-level 'policies:' list")

    policies = []
    for i, raw in enumerate(data["policies"]):
        try:
            policies.append(Policy.model_validate(raw))
        except ValidationError as exc:
            pid = raw.get("id", f"#{i}") if isinstance(raw, dict) else f"#{i}"
            issues = "; ".join(
                f"{'.'.join(str(loc) for loc in e['loc'])}: {e['msg']}" for e in exc.errors()
            )
            raise PolicyLoadError(f"{file}: policy {pid}: {issues}") from exc
    return policies
