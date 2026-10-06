"""Shared plumbing for offline coding-agent transcript importers.

Both importers (Claude Code, Codex) read a JSONL log written by another
process and are fail-loud: what they skip or cut is counted, so coverage gaps
are visible rather than implied.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Tool payloads carry file contents and command output, which are unbounded.
# Cap what is stored so one session cannot balloon the evidence database or
# stall the detectors; truncation is recorded in the payload.
DEFAULT_MAX_PAYLOAD_CHARS = 20_000


@dataclass
class ImportStats:
    """What the import saw, so coverage gaps are visible rather than implied."""

    records_read: int = 0
    events_written: int = 0
    malformed_lines: int = 0
    skipped_by_type: dict[str, int] = field(default_factory=dict)
    truncated_payloads: int = 0
    sessions: set[str] = field(default_factory=set)

    def skip(self, kind: str) -> None:
        self.skipped_by_type[kind] = self.skipped_by_type.get(kind, 0) + 1

    def summary(self) -> str:
        skipped = sum(self.skipped_by_type.values())
        return (
            f"{self.events_written} event(s) from {self.records_read} record(s) "
            f"across {len(self.sessions)} session(s); "
            f"{skipped} non-behaviour record(s) skipped, "
            f"{self.malformed_lines} malformed line(s), "
            f"{self.truncated_payloads} payload(s) truncated"
        )


def read_jsonl(path: Path, stats: ImportStats) -> Iterator[dict[str, Any]]:
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                stats.malformed_lines += 1
                continue
            if isinstance(record, dict):
                stats.records_read += 1
                yield record
            else:
                stats.malformed_lines += 1


def flatten(content: Any) -> str:
    """Render a string or a list of content blocks as text."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict):
                parts.append(str(block.get("text", block.get("type", ""))))
            else:
                parts.append(str(block))
        return "\n".join(parts)
    return str(content)


def clip(text: str, max_chars: int, stats: ImportStats) -> str:
    if len(text) <= max_chars:
        return text
    stats.truncated_payloads += 1
    return text[:max_chars] + f"\n…[truncated, {len(text) - max_chars} more characters]"


def clip_obj(obj: Any, max_chars: int, stats: ImportStats) -> Any:
    """Bound a tool input without destroying its structure where possible."""
    if isinstance(obj, dict):
        return {k: clip(v, max_chars, stats) if isinstance(v, str) else v for k, v in obj.items()}
    if isinstance(obj, str):
        return clip(obj, max_chars, stats)
    return obj
