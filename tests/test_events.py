import json

from aire.core.events import GENESIS_HASH, AuditEvent, EventType


def make_event(**overrides) -> AuditEvent:
    defaults = dict(
        session_id="sess-1",
        app="test-app",
        event_type=EventType.LLM_REQUEST,
        payload={"gen_ai.request.model": "claude-opus-4-8", "prompt": "hello"},
    )
    defaults.update(overrides)
    return AuditEvent(**defaults)


def test_sealed_event_is_intact():
    event = make_event().sealed()
    assert event.hash
    assert event.is_intact()


def test_unsealed_event_is_not_intact():
    assert not make_event().is_intact()


def test_any_field_change_breaks_intactness():
    event = make_event().sealed()
    for field, value in [
        ("ts", "2026-01-01T00:00:00+00:00"),
        ("session_id", "other"),
        ("app", "other-app"),
        ("event_type", EventType.LLM_RESPONSE),
        ("payload", {"prompt": "tampered"}),
        ("prev_hash", "f" * 64),
    ]:
        tampered = event.model_copy(update={field: value})
        assert not tampered.is_intact(), f"tampering {field} went undetected"


def test_canonical_body_is_deterministic_and_key_order_independent():
    a = make_event(payload={"b": 2, "a": 1})
    b = a.model_copy(update={"payload": {"a": 1, "b": 2}})
    assert a.canonical_body() == b.canonical_body()
    assert a.compute_hash() == b.compute_hash()


def test_canonical_body_excludes_hash():
    event = make_event()
    assert event.sealed().canonical_body() == event.canonical_body()
    body = json.loads(event.canonical_body())
    assert "hash" not in body
    assert body["prev_hash"] == GENESIS_HASH  # prev_hash stays in — it links the chain


def test_default_ids_are_unique_and_sortable():
    ids = [make_event().event_id for _ in range(50)]
    assert len(set(ids)) == 50
    assert ids == sorted(ids)  # ULIDs generated in sequence sort by time
