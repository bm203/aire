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
    """Load internal-channel traces.

    With no ``data_dir`` the synthetic CI fixture is used. If ``data_dir`` is
    given it must contain the dataset — a missing file raises rather than
    silently falling back to the fixture, so a mistyped path can't masquerade
    as a real run.
    """
    if data_dir is not None:
        path = Path(data_dir) / "traces_internal_channels.jsonl"
        if not path.exists():
            raise FileNotFoundError(
                f"{path} not found — pass the AgentLeak "
                "agentleak_data/datasets directory, or omit --agentleak-data "
                "to use the synthetic CI fixture"
            )
    else:
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


# --- Private-vault PII corpus (larger-N recall, complements the 3 traces) ----
#
# AgentLeak ships 1000 scenario *definitions*, each with a private_vault of
# records about people (patient / customer / candidate / employee / client).
# These are not executed traces, so this is NOT a leakage measurement — it is
# an honestly-scoped **PII-detection recall** metric: given the sensitive
# records AgentLeak defines, does AIRE's memory PII detector surface them when
# they are written to agent memory? Ground truth is field-name based and
# transparent: a record is PII-positive if it carries any identity field.

_VAULT_FIXTURE = Path(__file__).parent / "fixtures" / "agentleak_vault_records.jsonl"
_PII_FIELDS = frozenset(
    {
        "name",
        "full_name",
        "first_name",
        "last_name",
        "patient_name",
        "client_name",
        "candidate_name",
        "employee_name",
        "ssn",
        "email",
        "phone",
        "dob",
        "address",
    }
)


@dataclass
class VaultRecord:
    scenario_id: str
    record_type: str
    text: str
    has_pii: bool  # ground truth: carries an identity field


def load_vault_records(
    data_dir: Path | None = None, *, limit: int | None = None
) -> list[VaultRecord]:
    """Load private-vault records (fixture when no ``data_dir``).

    Uses ``scenarios_base_100.jsonl`` from the dataset. A missing file raises
    rather than silently using the fixture.
    """
    if data_dir is not None:
        path = Path(data_dir) / "scenarios_base_100.jsonl"
        if not path.exists():
            raise FileNotFoundError(
                f"{path} not found — pass the AgentLeak agentleak_data/datasets "
                "directory, or omit --agentleak-data to use the synthetic fixture"
            )
    else:
        path = _VAULT_FIXTURE

    records: list[VaultRecord] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        scenario = json.loads(line)
        sid = str(scenario.get("scenario_id", "?"))
        for rec in scenario.get("private_vault", {}).get("records", []):
            fields = rec.get("fields") or {}
            has_pii = any(k in _PII_FIELDS for k in fields)
            # Text = the record's field values (what would land in memory).
            text = " | ".join(f"{k}: {v}" for k, v in fields.items())
            records.append(
                VaultRecord(
                    scenario_id=sid,
                    record_type=str(rec.get("record_type", "?")),
                    text=text,
                    has_pii=has_pii,
                )
            )
            if limit is not None and len(records) >= limit:
                return records
    return records


@dataclass
class VaultResult:
    records_total: int
    identity_records: int  # records with an explicit identity field (ground-truth positives)
    identity_detected: int  # of those, how many the detector flagged
    non_identity_records: int  # records without an explicit identity field
    non_identity_flagged: int  # of those, how many the detector still flagged (PII in free text)
    data_source: str

    @property
    def recall(self) -> float:
        return self.identity_detected / self.identity_records if self.identity_records else 0.0

    def as_dict(self) -> dict:
        return {
            "metric": "private_vault_pii_recall",
            "note": (
                "Honestly scoped: PII-detection RECALL over AgentLeak private-vault "
                "records that carry an explicit identity field (ground truth is "
                "field-name based). Not precision — the remaining records are not "
                "reliable PII-free negatives (records are about people; names appear "
                "in free-text fields too), so records flagged without an identity "
                "field are reported separately as PII-in-free-text, not as errors."
            ),
            "data_source": self.data_source,
            "records_total": self.records_total,
            "identity_records": self.identity_records,
            "identity_detected": self.identity_detected,
            "recall": round(self.recall, 4),
            "non_identity_records": self.non_identity_records,
            "non_identity_flagged_in_free_text": self.non_identity_flagged,
        }


def run_vault_pii(
    store: EvidenceStore, records: list[VaultRecord], detector: Detector
) -> VaultResult:
    """Replay each vault record as a memory.write; score PII-detection recall."""
    label_by_event: dict[str, VaultRecord] = {}
    for i, rec in enumerate(records):
        event = store.append(
            session_id=f"vault-{rec.scenario_id}-{i}",
            app="eval.agentleak.vault",
            event_type=EventType.MEMORY_WRITE,
            payload={
                "thread_id": f"vault-{rec.scenario_id}-{i}",
                "channel_values": {"record": rec.text},
            },
        )
        label_by_event[event.event_id] = rec

    events = list(store.events(event_type=EventType.MEMORY_WRITE))
    findings = detector.inspect(events, store)
    flagged = {eid for f in findings for eid in f.source_event_ids}

    identity = identity_hit = non_identity = non_identity_hit = 0
    for event in events:
        rec = label_by_event.get(event.event_id)
        if rec is None:
            continue
        hit = event.event_id in flagged
        if rec.has_pii:
            identity += 1
            identity_hit += hit
        else:
            non_identity += 1
            non_identity_hit += hit

    is_fixture = all(r.scenario_id.startswith("SYNTH") for r in records) if records else True
    return VaultResult(
        records_total=len(records),
        identity_records=identity,
        identity_detected=identity_hit,
        non_identity_records=non_identity,
        non_identity_flagged=non_identity_hit,
        data_source="fixture" if is_fixture else "dataset",
    )


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
