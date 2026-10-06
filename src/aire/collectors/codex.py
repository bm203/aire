"""Offline importer for OpenAI Codex session rollouts.

Codex records each session as a JSONL "rollout" under
``~/.codex/sessions/YYYY/MM/DD/rollout-<timestamp>-<thread-id>.jsonl``. This
module maps it onto AIRE's event model, producing the same event shapes as the
Claude Code importer, so detectors, policies and reports need no changes.

Usage::

    from aire.collectors.codex import import_rollout
    from aire.store import EvidenceStore

    store = EvidenceStore("evidence.db")
    stats = import_rollout("~/.codex/sessions/2026/10/01/rollout-....jsonl", store=store)

The same two properties as the Claude Code importer apply. **Imported, not
observed:** the chain proves nothing changed after ingestion, not that the
rollout is faithful. **Fail-loud:** skipped and malformed records are counted
and reported, because silently dropping them would understate what the agent did.

Format: each line is ``{"timestamp", "ordinal"?, "type", "payload"}``. The
model-visible history is in ``response_item`` lines (messages, reasoning, tool
calls and their outputs). ``event_msg`` lines are UI events that largely
duplicate those items and are skipped and counted, so nothing is double-counted.
The format is internal to Codex and carries no stability guarantee; this
mapping follows the open-source definitions at openai/codex commit d6c3b44
(Oct 2026). Unknown types are skipped and counted rather than treated as errors.

Codex compresses cold rollouts to ``.jsonl.zst``. Python 3.12 has no zstd in
the standard library, so compressed files are refused with an instruction to
decompress them first rather than silently read as empty.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aire.collectors._transcript import (
    DEFAULT_MAX_PAYLOAD_CHARS,
    ImportStats,
    clip,
    clip_obj,
    flatten,
    read_jsonl,
)
from aire.core.events import EventType
from aire.store import EvidenceStore

__all__ = ["DEFAULT_APP", "DEFAULT_MAX_PAYLOAD_CHARS", "ImportStats", "import_rollout"]

DEFAULT_APP = "codex"

_ROLLOUT_NAME = re.compile(r"rollout-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-([0-9a-fA-F-]{36})")

# Response items that are a tool invocation, with the tool name to record when
# the item carries none (hosted and legacy tools are typed, not named).
_TYPED_TOOLS = {
    "local_shell_call": "local_shell",
    "web_search_call": "web_search",
    "tool_search_call": "tool_search",
}


@dataclass
class _Session:
    """Session-level facts the rollout records once and items rely on."""

    session_id: str
    cwd: str | None = None
    git_branch: str | None = None
    cli_version: str | None = None
    model: str | None = None
    # call_id -> tool name: outputs reference their call by id only.
    tool_names: dict[str, str] = field(default_factory=dict)


def import_rollout(
    path: str | Path,
    *,
    store: EvidenceStore,
    app: str | None = None,
    max_payload_chars: int = DEFAULT_MAX_PAYLOAD_CHARS,
) -> ImportStats:
    """Read a Codex rollout and append its events to ``store``."""
    path = Path(path).expanduser()
    if not path.exists():
        raise FileNotFoundError(f"no such rollout: {path}")
    if path.suffix == ".zst":
        raise ValueError(
            f"{path.name} is zstd-compressed; decompress it first "
            f"(zstd -d {path.name}) and import the .jsonl"
        )

    stats = ImportStats()
    m = _ROLLOUT_NAME.search(path.name)
    session = _Session(session_id=m.group(1) if m else path.stem)
    app_name = app or DEFAULT_APP

    for record in read_jsonl(path, stats):
        rtype = str(record.get("type"))
        payload = record.get("payload")
        if not isinstance(payload, dict):
            stats.skip(rtype)
            continue

        if rtype == "session_meta":
            session.session_id = str(payload.get("id") or session.session_id)
            session.cwd = payload.get("cwd") or session.cwd
            session.cli_version = payload.get("cli_version")
            git = payload.get("git") if isinstance(payload.get("git"), dict) else {}
            session.git_branch = git.get("branch")
            stats.skip(rtype)
            continue
        if rtype == "turn_context":
            # The model is a per-turn setting recorded before the turn's items,
            # so requests can carry it (unlike Claude Code, where it is only
            # known from responses).
            session.model = payload.get("model") or session.model
            session.cwd = payload.get("cwd") or session.cwd
            stats.skip(rtype)
            continue
        if rtype != "response_item":
            stats.skip(rtype)
            continue

        events = list(_events_for(payload, record, session, max_payload_chars, stats))
        if not events:
            stats.skip(f"response_item:{_item_kind(payload)}")
            continue
        stats.sessions.add(session.session_id)
        for event_type, event_payload in events:
            store.append(
                session_id=session.session_id,
                app=app_name,
                event_type=event_type,
                payload=event_payload,
            )
            stats.events_written += 1

    return stats


def _item_kind(item: dict[str, Any]) -> str:
    kind = str(item.get("type"))
    return f"{kind}:{item.get('role')}" if kind == "message" else kind


def _events_for(
    item: dict[str, Any],
    record: dict[str, Any],
    session: _Session,
    max_chars: int,
    stats: ImportStats,
) -> Iterator[tuple[EventType, dict[str, Any]]]:
    kind = item.get("type")
    origin = _origin(record, session)

    if kind == "message":
        text = flatten(item.get("content"))
        role = item.get("role")
        if role == "user":
            payload: dict[str, Any] = {
                "gen_ai.system": "openai",
                "gen_ai.operation.name": "chat",
                "messages": [{"role": "user", "content": clip(text, max_chars, stats)}],
                **origin,
            }
            if session.model is not None:
                payload["gen_ai.request.model"] = session.model
            yield (EventType.LLM_REQUEST, payload)
        elif role == "assistant":
            yield (
                EventType.LLM_RESPONSE,
                {
                    "gen_ai.system": "openai",
                    "gen_ai.response.id": item.get("id"),
                    "gen_ai.response.model": session.model,
                    "content": clip(text, max_chars, stats),
                    "codex.phase": item.get("phase"),
                    **origin,
                },
            )
        # developer/system messages are harness instructions, not behaviour:
        # nothing is yielded, so the caller counts them as skipped.
        return

    if kind in ("function_call", "custom_tool_call") or kind in _TYPED_TOOLS:
        name = str(item.get("name") or _TYPED_TOOLS.get(str(kind), kind))
        call_id = item.get("call_id")
        if call_id:
            session.tool_names[str(call_id)] = name
        if kind == "function_call":
            tool_input = _parse_arguments(item.get("arguments"))
        elif kind == "custom_tool_call":
            tool_input = item.get("input")
        elif kind == "local_shell_call":
            tool_input = item.get("action")
        else:
            tool_input = item.get("action") or item.get("arguments")
        yield (
            EventType.TOOL_CALL,
            {
                "gen_ai.tool.name": name,
                "tool_use_id": call_id,
                "input": clip_obj(tool_input, max_chars, stats),
                **origin,
            },
        )
        return

    if kind in ("function_call_output", "custom_tool_call_output", "tool_search_output"):
        call_id = item.get("call_id")
        name = item.get("name") or session.tool_names.get(str(call_id))
        if kind == "tool_search_output":
            content = json.dumps(item.get("tools"), ensure_ascii=False)
            name = name or "tool_search"
        else:
            content = flatten(item.get("output"))
        yield (
            EventType.TOOL_RESULT,
            {
                "tool_use_id": call_id,
                "gen_ai.tool.name": name,
                "content": clip(content, max_chars, stats),
                # The rollout does not persist whether a tool call succeeded.
                "is_error": None,
                **origin,
            },
        )
        return

    if kind == "agent_message":
        # A message from another agent entering this one: an internal channel,
        # recorded like a tool result so content detectors scan it.
        yield (
            EventType.TOOL_RESULT,
            {
                "gen_ai.tool.name": "agent_message",
                "codex.author": item.get("author"),
                "codex.recipient": item.get("recipient"),
                "content": clip(flatten(item.get("content")), max_chars, stats),
                "is_error": None,
                **origin,
            },
        )
        return
    # reasoning, compaction, image generation, configuration and unknown items:
    # nothing yielded; counted by the caller. Reasoning is model-internal rather
    # than an action or an output, as in the Claude Code importer.


def _parse_arguments(arguments: Any) -> Any:
    """Function-call arguments arrive as a JSON string; keep the raw string if not JSON."""
    if not isinstance(arguments, str):
        return arguments
    try:
        return json.loads(arguments)
    except json.JSONDecodeError:
        return arguments


def _origin(record: dict[str, Any], session: _Session) -> dict[str, Any]:
    """Provenance from the source log (see the Claude Code importer for why both times)."""
    return {
        "source.type": "codex-rollout",
        "source.timestamp": record.get("timestamp"),
        "source.ordinal": record.get("ordinal"),
        "source.cwd": session.cwd,
        "source.git_branch": session.git_branch,
        "source.cli_version": session.cli_version,
    }
