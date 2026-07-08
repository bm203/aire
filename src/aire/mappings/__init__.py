"""Framework mappings: resolve framework_refs to auditable citations.

Mappings live in YAML (one file per framework) so governance teams can update
citations without touching code. A ref key has the form
``<FRAMEWORK>:<control-id>``, e.g. ``EU-AI-ACT:Art.12``.

These files are the single source of truth: the shipped policies/detectors
are CI-checked against them (every ref must resolve), and the public
framework-mapping doc is generated from them (``aire mappings``).

Control titles were verified against the published sources (EU AI Act
articles, ISO/IEC 42001:2023 Annex A titles, NIST AI RMF 1.0 subcategories,
OWASP LLM Top 10 2025). Only titles are reproduced — never standard body
text (ISO text is proprietary).
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict

_MAPPINGS_DIR = Path(__file__).parent


class Citation(BaseModel):
    model_config = ConfigDict(frozen=True)

    ref: str  # "EU-AI-ACT:Art.12"
    framework: str  # "EU-AI-ACT"
    framework_name: str
    control_id: str  # "Art.12"
    title: str
    url: str | None = None


class MappingError(Exception):
    pass


class FrameworkMappings:
    def __init__(self, citations: dict[str, Citation]) -> None:
        self._citations = citations

    @classmethod
    def load(cls, directory: str | Path | None = None) -> FrameworkMappings:
        directory = Path(directory) if directory else _MAPPINGS_DIR
        citations: dict[str, Citation] = {}
        for file in sorted(directory.glob("*.yaml")):
            data = yaml.safe_load(file.read_text())
            if not isinstance(data, dict) or "framework" not in data:
                raise MappingError(f"{file}: expected keys 'framework', 'name', 'controls'")
            framework = str(data["framework"])
            name = str(data.get("name", framework))
            base_url = data.get("url")
            controls = data.get("controls") or {}
            for control_id, control in controls.items():
                ref = f"{framework}:{control_id}"
                if ref in citations:
                    raise MappingError(f"{file}: duplicate control ref {ref!r}")
                citations[ref] = Citation(
                    ref=ref,
                    framework=framework,
                    framework_name=name,
                    control_id=str(control_id),
                    title=str(control.get("title", "")),
                    url=control.get("url", base_url),
                )
        if not citations:
            raise MappingError(f"{directory}: no mapping files found")
        return cls(citations)

    def resolve(self, refs: list[str]) -> tuple[list[Citation], list[str]]:
        """Return (resolved citations, unknown refs) — unknowns are surfaced,
        never silently dropped: an auditor must see a dangling reference."""
        resolved, unknown = [], []
        for ref in refs:
            citation = self._citations.get(ref)
            if citation is None:
                unknown.append(ref)
            else:
                resolved.append(citation)
        return resolved, unknown

    def all_citations(self) -> list[Citation]:
        return sorted(self._citations.values(), key=lambda c: (c.framework, c.control_id))
