"""Framework-mapping tests, including the ref-integrity CI check:
every framework_ref shipped in builtin policies or detectors MUST resolve."""

import pytest

from aire.mappings import FrameworkMappings, MappingError
from aire.policy import builtin_policies


@pytest.fixture(scope="module")
def mappings():
    return FrameworkMappings.load()


def shipped_refs() -> set[str]:
    refs: set[str] = set()
    for policy in builtin_policies():
        refs.update(policy.framework_refs)
    from aire.detectors import completeness, pii, prompt_injection

    refs.update(completeness._FRAMEWORK_REFS)
    refs.update(pii._FRAMEWORK_REFS)
    refs.update(prompt_injection._FRAMEWORK_REFS)
    try:
        from aire.detectors import memory_retention

        refs.update(memory_retention._REFS_DELETION)
        refs.update(memory_retention._REFS_RETENTION)
        refs.update(memory_retention._REFS_PII)
        refs.update(memory_retention._REFS_XSESSION)
    except ImportError:
        pass
    return refs


class TestMappings:
    def test_loads_all_four_frameworks(self, mappings):
        frameworks = {c.framework for c in mappings.all_citations()}
        assert frameworks == {"EU-AI-ACT", "ISO42001", "NIST-AI-RMF", "OWASP-LLM"}

    def test_every_shipped_ref_resolves(self, mappings):
        """The CI check: a dangling ref would produce uncited findings."""
        refs = shipped_refs()
        assert refs, "no shipped refs collected — collection is broken"
        _, unknown = mappings.resolve(sorted(refs))
        assert unknown == [], f"shipped refs missing from mappings: {unknown}"

    def test_resolve_surfaces_unknown_refs(self, mappings):
        resolved, unknown = mappings.resolve(["EU-AI-ACT:Art.12", "BOGUS:X.1"])
        assert [c.ref for c in resolved] == ["EU-AI-ACT:Art.12"]
        assert unknown == ["BOGUS:X.1"]

    def test_citations_carry_titles(self, mappings):
        for citation in mappings.all_citations():
            assert citation.title, f"{citation.ref} has no title"

    def test_missing_directory_errors(self, tmp_path):
        with pytest.raises(MappingError):
            FrameworkMappings.load(tmp_path)

    def test_duplicate_control_rejected(self, tmp_path):
        content = 'framework: X\nname: X\ncontrols:\n  "C.1":\n    title: t\n'
        (tmp_path / "a.yaml").write_text(content)
        (tmp_path / "b.yaml").write_text(content)
        with pytest.raises(MappingError, match="duplicate"):
            FrameworkMappings.load(tmp_path)
