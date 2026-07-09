"""AgentLeak internal-channel leakage evaluation (arXiv 2602.11510).

AgentLeak's thesis: multi-agent systems leak PII through *internal* channels —
inter-agent messages and shared memory — that final-output audits never
inspect. AIRE records exactly those channels as evidence events, so its PII
detector can see them.

This harness replays AgentLeak's internal-channel traces through AIRE:

- a channel carrying an inter-agent message → a ``tool.result`` event
- a channel carrying shared-memory content → a ``memory.write`` event

Ground truth is the trace's ``pii_exposed`` list (non-empty ⇒ the channel
carries PII). We measure, per channel type, whether AIRE's PII detector
surfaces the channel — i.e. recall on internal-channel leakage. An
output-only auditor would surface **zero** of these channels; that coverage
gap is the headline.

Data: point ``--agentleak-data`` at the cloned AgentLeak repo's
``agentleak_data/datasets`` directory (MIT-licensed). A tiny synthetic
fixture with fake PII ships for CI so the harness runs without the dataset.
Requires the ``pii`` extra (Presidio) for real detection.

Security: traces are parsed as JSON data only; the generated report contains
counts and rates, never the PII strings themselves.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from aire.core.events import EventType
from aire.detectors.base import Detector
from aire.store import EvidenceStore
from evals.metrics import ConfusionMatrix

_FIXTURE = Path(__file__).parent / "fixtures" / "agentleak_traces.jsonl"


@dataclass
class Channel:
    trace_id: str
    channel_id: str
    kind: str  # "inter_agent" | "shared_memory" | "other"
    content: str
    carries_pii: bool


def _classify(channel_id: str, channel: dict) -> Channel | None:
    if "message" in channel:
        kind, content = "inter_agent", channel["message"]
    elif "memory_value" in channel:
        kind, content = "shared_memory", channel["memory_value"]
    elif "content" in channel:
        kind, content = "other", channel["content"]
    else:
        return None
    return Channel(
        trace_id="",
        channel_id=channel_id,
        kind=kind,
        content=str(content),
        carries_pii=bool(channel.get("pii_exposed")),
    )


def load_channels(data_dir: Path | None = None) -> list[Channel]:
    """Load internal-channel traces, falling back to the CI fixture."""
    path = None
    if data_dir is not None:
        candidate = Path(data_dir) / "traces_internal_channels.jsonl"
        if candidate.exists():
            path = candidate
    if path is None:
        path = _FIXTURE

    channels: list[Channel] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        trace = json.loads(line)
        trace_id = str(trace.get("scenario_id", "?"))
        for key, value in trace.items():
            if key.startswith("channel_") and isinstance(value, dict):
                channel = _classify(key, value)
                if channel is not None:
                    channel.trace_id = trace_id
                    channels.append(channel)
    return channels


@dataclass
class AgentLeakResult:
    overall: ConfusionMatrix
    by_kind: dict[str, ConfusionMatrix]
    channels_total: int
    data_source: str
    missed: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "benchmark": "AgentLeak",
            "arxiv": "2602.11510",
            "data_source": self.data_source,
            "channels_total": self.channels_total,
            "internal_channel_recall": self.overall.as_dict(),
            "by_channel_kind": {k: v.as_dict() for k, v in self.by_kind.items()},
            "output_only_auditor_coverage": 0.0,  # the headline contrast
            "missed_channels_sample": self.missed[:20],
        }


def run(store: EvidenceStore, channels: list[Channel], detector: Detector) -> AgentLeakResult:
    """Replay channels as evidence events; measure PII-detection recall."""
    label_by_event: dict[str, Channel] = {}
    for i, channel in enumerate(channels):
        if channel.kind == "shared_memory":
            event = store.append(
                session_id=f"leak-{channel.trace_id}",
                app="eval.agentleak",
                event_type=EventType.MEMORY_WRITE,
                payload={
                    "thread_id": f"leak-{channel.trace_id}",
                    "channel_values": {"content": channel.content},
                },
            )
        else:  # inter_agent / other → tool.result (an internal, non-output channel)
            event = store.append(
                session_id=f"leak-{channel.trace_id}",
                app="eval.agentleak",
                event_type=EventType.TOOL_RESULT,
                payload={"tool_use_id": f"ch-{i}", "content": channel.content},
            )
        label_by_event[event.event_id] = channel

    events = list(store.events())
    findings = detector.inspect(events, store)
    flagged = {eid for f in findings for eid in f.source_event_ids}

    overall = ConfusionMatrix()
    by_kind: dict[str, ConfusionMatrix] = {}
    missed: list[str] = []
    for event in events:
        channel = label_by_event.get(event.event_id)
        if channel is None:
            continue
        predicted = event.event_id in flagged
        overall.add(predicted=predicted, actual=channel.carries_pii)
        by_kind.setdefault(channel.kind, ConfusionMatrix()).add(
            predicted=predicted, actual=channel.carries_pii
        )
        if channel.carries_pii and not predicted:
            missed.append(f"{channel.trace_id}/{channel.channel_id}")

    return AgentLeakResult(
        overall=overall,
        by_kind=by_kind,
        channels_total=len(channels),
        data_source="fixture" if not _has_real_data(channels) else "dataset",
        missed=missed,
    )


def _has_real_data(channels: list[Channel]) -> bool:
    return any(not c.trace_id.startswith("SYNTH") for c in channels)
