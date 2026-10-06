"""Offline importer for Claude Code session transcripts.

Coding agents run with real shell, filesystem, and network access on developer
machines, yet most organisations cannot answer what one actually did in a given
session. Claude Code writes a complete JSONL transcript per session, so the
evidence already exists locally; this module maps it onto AIRE's event model so
the existing policy engine and detectors can be run over it.

Usage::

    from aire.collectors.claude_code import import_transcript
    from aire.store import EvidenceStore

    store = EvidenceStore("evidence.db")
    stats = import_transcript("~/.claude/projects/<proj>/<session>.jsonl", store=store)

Two properties differ from AIRE's live collectors, and both matter for how the
resulting evidence should be read:

**This is imported evidence, not observed evidence.** A live collector records
what it saw as the host ran, so the hash chain covers the observation itself.
Here AIRE reads a log written by another process, which could have been altered
before import. The chain proves nothing was changed *after* AIRE ingested it; it
cannot vouch for the transcript's own integrity.

**Import is fail-loud, not fail-open.** Live collectors swallow their own errors
so they can never break the host application. An import is an offline operation
with an operator watching, and silently dropping records would understate what
the agent did, so failures surface and skipped records are counted and reported.

The transcript format is internal to Claude Code and carries no stability
guarantee. Unknown record and block types are skipped and counted rather than
treated as errors, so a format change degrades coverage instead of breaking.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

from aire.collectors._transcript import (
    DEFAULT_MAX_PAYLOAD_CHARS,
    ImportStats,
    flatten,
    read_jsonl,
)
from aire.collectors._transcript import clip as _clip
from aire.collectors._transcript import clip_obj as _clip_obj
from aire.core.events import EventType
from aire.store import EvidenceStore

__all__ = ["DEFAULT_APP", "DEFAULT_MAX_PAYLOAD_CHARS", "ImportStats", "import_transcript"]

DEFAULT_APP = "claude-code"

# Record types that carry agent behaviour. Everything else in the transcript is
# UI or bookkeeping state (mode changes, title generation, file snapshots).
_BEHAVIOUR_TYPES = frozenset({"user", "assistant"})


def import_transcript(
    path: str | Path,
    *,
    store: EvidenceStore,
    app: str | None = None,
    max_payload_chars: int = DEFAULT_MAX_PAYLOAD_CHARS,
) -> ImportStats:
    """Read a Claude Code transcript and append its events to ``store``."""
    path = Path(path).expanduser()
    if not path.exists():
        raise FileNotFoundError(f"no such transcript: {path}")

    stats = ImportStats()
    # tool_use_id -> tool name, so a tool result can name the tool that produced
    # it. The transcript links them by id only, but policies and findings are far
    # more useful when they can say "WebFetch returned this" rather than "a tool did".
    tool_names: dict[str, str] = {}
    # The model is recorded on responses, never on requests, but it is a
    # session-level property in Claude Code. Carry the last observed model onto
    # subsequent requests so model-inventory policies can evaluate them; requests
    # before the first response simply have no model, which policies report as
    # not-evaluated rather than silently passing.
    session_models: dict[str, str] = {}

    for record in read_jsonl(path, stats):
        rtype = record.get("type")
        if rtype not in _BEHAVIOUR_TYPES:
            stats.skip(str(rtype))
            continue

        session_id = str(record.get("sessionId") or path.stem)
        stats.sessions.add(session_id)
        app_name = app or DEFAULT_APP

        for event_type, payload in _events_for(
            record, tool_names, session_models, session_id, max_payload_chars, stats
        ):
            store.append(
                session_id=session_id,
                app=app_name,
                event_type=event_type,
                payload=payload,
            )
            stats.events_written += 1

    return stats


def _events_for(
    record: dict[str, Any],
    tool_names: dict[str, str],
    session_models: dict[str, str],
    session_id: str,
    max_chars: int,
    stats: ImportStats,
) -> Iterator[tuple[EventType, dict[str, Any]]]:
    message = record.get("message")
    if not isinstance(message, dict):
        return
    content = message.get("content")
    origin = _origin(record)

    if record.get("type") == "user":
        # A user record is either a real prompt (content is a string) or the
        # tool results being fed back to the model (content is a block list).
        if isinstance(content, str):
            model = session_models.get(session_id)
            payload: dict[str, Any] = {
                "gen_ai.system": "anthropic",
                "gen_ai.operation.name": "chat",
                "messages": [{"role": "user", "content": _clip(content, max_chars, stats)}],
                **origin,
            }
            if model is not None:
                payload["gen_ai.request.model"] = model
            yield (EventType.LLM_REQUEST, payload)
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    tool_use_id = block.get("tool_use_id")
                    yield (
                        EventType.TOOL_RESULT,
                        {
                            "tool_use_id": tool_use_id,
                            "gen_ai.tool.name": tool_names.get(str(tool_use_id)),
                            "content": _clip(flatten(block.get("content")), max_chars, stats),
                            "is_error": bool(block.get("is_error", False)),
                            **origin,
                        },
                    )
        return

    # Assistant record: the response itself, plus one event per tool invocation.
    blocks = content if isinstance(content, list) else []
    texts: list[str] = []
    block_counts: dict[str, int] = {}
    tool_uses: list[dict[str, Any]] = []
    for block in blocks:
        if not isinstance(block, dict):
            continue
        btype = str(block.get("type"))
        block_counts[btype] = block_counts.get(btype, 0) + 1
        if btype == "text":
            texts.append(str(block.get("text", "")))
        elif btype == "tool_use":
            tool_uses.append(block)
            if block.get("id"):
                tool_names[str(block["id"])] = str(block.get("name", ""))

    if message.get("model"):
        session_models[session_id] = str(message["model"])

    usage = message.get("usage") if isinstance(message.get("usage"), dict) else {}
    yield (
        EventType.LLM_RESPONSE,
        {
            "gen_ai.system": "anthropic",
            "gen_ai.response.id": message.get("id"),
            "gen_ai.response.model": message.get("model"),
            "gen_ai.response.finish_reasons": [message.get("stop_reason")],
            "gen_ai.usage.input_tokens": usage.get("input_tokens"),
            "gen_ai.usage.output_tokens": usage.get("output_tokens"),
            "content": _clip("\n".join(texts), max_chars, stats),
            # Reasoning content is deliberately not stored: it is model-internal
            # rather than an action or an output, and it dominates payload size.
            # The count is kept so its presence stays visible to an auditor.
            "block_counts": block_counts,
            **_origin(record),
        },
    )

    for block in tool_uses:
        yield (
            EventType.TOOL_CALL,
            {
                "gen_ai.tool.name": block.get("name"),
                "tool_use_id": block.get("id"),
                "input": _clip_obj(block.get("input"), max_chars, stats),
                **_origin(record),
            },
        )


def _origin(record: dict[str, Any]) -> dict[str, Any]:
    """Provenance from the source log.

    ``source.timestamp`` is the transcript's own time. The event's ``ts`` is when
    AIRE ingested it, so both are kept: the chain orders ingestion, the payload
    preserves when the agent actually acted.
    """
    return {
        "source.type": "claude-code-transcript",
        "source.timestamp": record.get("timestamp"),
        "source.uuid": record.get("uuid"),
        "source.cwd": record.get("cwd"),
        "source.git_branch": record.get("gitBranch"),
    }
