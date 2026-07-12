"""Presidio-backed PII detector tests (skipped without the pii extra + model)."""

import json

import pytest

pytest.importorskip("presidio_analyzer")
spacy = pytest.importorskip("spacy")
if not spacy.util.is_package("en_core_web_sm"):
    pytest.skip("spaCy model en_core_web_sm not installed", allow_module_level=True)

from aire.core.events import EventType  # noqa: E402
from aire.detectors import DetectorRunner  # noqa: E402
from aire.detectors.pii import DEFAULT_PII_ENTITIES, PIIDetector, PresidioScanner  # noqa: E402
from aire.store import EvidenceStore  # noqa: E402


@pytest.fixture(scope="module")
def detector():
    return PIIDetector(scanner=PresidioScanner(model="en_core_web_sm"))


@pytest.fixture
def store(tmp_path):
    s = EvidenceStore(tmp_path / "evidence.db")
    yield s
    s.close()


class TestPIIDetector:
    def test_email_in_request_is_found_without_copying_the_value(self, store, detector):
        store.append(
            session_id="s",
            app="t",
            event_type=EventType.LLM_REQUEST,
            payload={
                "messages": [
                    {"role": "user", "content": "My email is alice@example.com, please update it"}
                ]
            },
        )
        outcome = DetectorRunner([detector]).run(store)
        [rec] = outcome.recorded
        assert rec.payload["detail"]["entity_counts"].get("EMAIL_ADDRESS") == 1
        assert rec.payload["severity"] == "medium"
        # offsets + types only — the raw address never re-appears in the finding
        assert "alice@example.com" not in json.dumps(rec.payload)

    def test_pii_in_memory_write_is_high_severity(self, store, detector):
        store.append(
            session_id="s",
            app="t",
            event_type=EventType.MEMORY_WRITE,
            payload={
                "thread_id": "s",
                "channel_values": {
                    "messages": [{"role": "user", "content": "reach me at bob@example.org"}]
                },
            },
        )
        outcome = DetectorRunner([detector]).run(store)
        [rec] = outcome.recorded
        assert rec.payload["severity"] == "high"
        assert "memory.write" in rec.payload["summary"]

    def test_clean_content_is_quiet(self, store, detector):
        store.append(
            session_id="s",
            app="t",
            event_type=EventType.LLM_REQUEST,
            payload={"messages": [{"role": "user", "content": "The dashboard renders slowly"}]},
        )
        outcome = DetectorRunner([detector]).run(store)
        assert outcome.recorded == []


class TestDefaultEntities:
    """The default scanner is tuned to high-signal identifiers, not Presidio's
    full recognizer list — a URL alone is not treated as personal data."""

    _URL_TEXT = "Docs are at https://wiki.example.com/runbook/pump-07 — see section 3."

    def test_default_ignores_url_noise(self, store):
        detector = PIIDetector(scanner=PresidioScanner(entities=DEFAULT_PII_ENTITIES))
        store.append(
            session_id="s", app="t", event_type=EventType.LLM_REQUEST,
            payload={"messages": [{"role": "user", "content": self._URL_TEXT}]},
        )
        outcome = DetectorRunner([detector]).run(store)
        assert outcome.recorded == []  # URL is not in the default set

    def test_scanner_default_matches_shared_constant(self, store):
        # No explicit entities => the shipped tuned set (single source of truth).
        detector = PIIDetector(scanner=PresidioScanner())
        store.append(
            session_id="s", app="t", event_type=EventType.LLM_REQUEST,
            payload={"messages": [{"role": "user", "content": self._URL_TEXT}]},
        )
        assert DetectorRunner([detector]).run(store).recorded == []

    def test_explicit_override_can_widen(self, store):
        # Opting into URL detection re-enables it — the override path works.
        detector = PIIDetector(scanner=PresidioScanner(entities=["URL"]))
        store.append(
            session_id="s", app="t", event_type=EventType.LLM_REQUEST,
            payload={"messages": [{"role": "user", "content": self._URL_TEXT}]},
        )
        [rec] = DetectorRunner([detector]).run(store).recorded
        assert rec.payload["detail"]["entity_counts"].get("URL", 0) >= 1
