"""V2 industrial IT/OT scenario tests (skipped without Presidio + langgraph)."""

import pytest

pytest.importorskip("presidio_analyzer")
pytest.importorskip("langgraph.checkpoint.sqlite")
spacy = pytest.importorskip("spacy")
if not spacy.util.is_package("en_core_web_sm"):
    pytest.skip("spaCy model en_core_web_sm not installed", allow_module_level=True)

from evals.industrial import run, scenario  # noqa: E402


class TestScenarioBuild:
    def test_ground_truth_is_labeled(self, tmp_path):
        gt = scenario.build(tmp_path / "e.db", tmp_path / "m.db")
        assert len(gt.injection_event_ids) == 1
        assert len(gt.pii_internal_event_ids) == 2
        assert len(gt.cross_clearance_event_ids) == 1
        assert gt.unhonored_deletion_threads == {"wo-4471"}
        assert len(gt.clean_event_ids) == 3
        assert gt.evidence_db.exists() and gt.memory_db.exists()


class TestDetectionCoverage:
    @pytest.fixture(scope="class")
    def results(self, tmp_path_factory):
        out = tmp_path_factory.mktemp("industrial") / "RESULTS.md"
        return run.run(out), out

    def test_every_planted_condition_is_caught(self, results):
        r, _ = results
        for name, cat in r["categories"].items():
            assert cat["complete"], f"{name}: only {cat['caught']}/{cat['planted']} caught"

    def test_no_false_positives_on_clean_events(self, results):
        r, _ = results
        conf = r["event_confusion"]
        assert conf["fp"] == 0
        assert conf["recall"] == 1.0
        assert conf["precision"] == 1.0

    def test_output_only_auditor_sees_nothing(self, results):
        r, _ = results
        assert r["internal_channel_conditions"] > 0
        assert r["output_only_auditor_coverage"] == 0

    def test_report_is_critical_and_chain_intact(self, results):
        r, _ = results
        assert r["report_overall_risk"] == "critical"
        assert r["chain_intact"] is True

    def test_results_markdown_contains_no_pii(self, results):
        _, out = results
        text = out.read_text()
        for pii in ["Morgan Avery", "morgan.avery@example.com", "0175"]:
            assert pii not in text
