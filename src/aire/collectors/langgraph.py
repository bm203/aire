"""Observe-only collector for LangGraph checkpointers (agent memory).

Wraps any ``BaseCheckpointSaver`` (SqliteSaver, PostgresSaver, MemorySaver,
…) and records ``memory.write`` / ``memory.read`` / ``memory.delete`` events
alongside every checkpointer operation. The inner saver's behavior is
untouched — reads and writes pass through unchanged, and host errors
propagate; only AIRE's own recording is fail-open.

Requires the ``aire[langgraph]`` extra (the ``langgraph-checkpoint``
interface package, not full LangGraph).

Usage::

    from langgraph.checkpoint.sqlite import SqliteSaver
    from aire.collectors.langgraph import InstrumentedSaver

    saver = InstrumentedSaver(SqliteSaver(conn), store=store, app="my-app")
    # pass `saver` wherever a checkpointer is expected
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from typing import Any

try:
    from langgraph.checkpoint.base import BaseCheckpointSaver
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "aire.collectors.langgraph requires the 'langgraph' extra: "
        "pip install 'aire[langgraph]'"
    ) from exc

from aire.collectors.base import Sensor, jsonable
from aire.core.events import EventType
from aire.store import EvidenceStore

_MEMORY_SYSTEM = "langgraph.checkpointer"


def _thread_id(config: dict[str, Any] | None) -> str | None:
    try:
        return (config or {}).get("configurable", {}).get("thread_id")
    except Exception:
        return None


class InstrumentedSaver(BaseCheckpointSaver):
    """Delegating checkpointer that emits audit events for memory operations."""

    def __init__(self, inner: BaseCheckpointSaver, *, store: EvidenceStore, app: str) -> None:
        super().__init__(serde=inner.serde)
        self._inner = inner
        self._sensor = Sensor(store=store, app=app)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    # -- sync interface ------------------------------------------------------

    def get_tuple(self, config: dict[str, Any]) -> Any:
        result = self._inner.get_tuple(config)
        tid = _thread_id(config)
        self._sensor.record(
            EventType.MEMORY_READ,
            lambda: {
                "memory.system": _MEMORY_SYSTEM,
                "op": "get",
                "thread_id": tid,
                "found": result is not None,
                "checkpoint_id": _thread_safe_checkpoint_id(result),
            },
            session_id=tid,
        )
        return result

    def list(self, config: dict[str, Any] | None, **kwargs: Any) -> Iterator[Any]:
        tid = _thread_id(config)
        self._sensor.record(
            EventType.MEMORY_READ,
            lambda: {"memory.system": _MEMORY_SYSTEM, "op": "list", "thread_id": tid},
            session_id=tid,
        )
        return self._inner.list(config, **kwargs)

    def put(
        self,
        config: dict[str, Any],
        checkpoint: dict[str, Any],
        metadata: dict[str, Any],
        new_versions: dict[str, Any],
    ) -> dict[str, Any]:
        result = self._inner.put(config, checkpoint, metadata, new_versions)
        tid = _thread_id(config)
        self._sensor.record(
            EventType.MEMORY_WRITE,
            lambda: {
                "memory.system": _MEMORY_SYSTEM,
                "op": "put",
                "thread_id": tid,
                "checkpoint_id": checkpoint.get("id"),
                "checkpoint_ts": checkpoint.get("ts"),
                # Full values recorded on purpose: the PII detector and the
                # memory retention/deletion control inspect this content.
                "channel_values": jsonable(checkpoint.get("channel_values")),
                "metadata": jsonable(metadata),
            },
            session_id=tid,
        )
        return result

    def put_writes(
        self,
        config: dict[str, Any],
        writes: Sequence[tuple[str, Any]],
        task_id: str,
        task_path: str = "",
    ) -> None:
        self._inner.put_writes(config, writes, task_id, task_path)
        tid = _thread_id(config)
        self._sensor.record(
            EventType.MEMORY_WRITE,
            lambda: {
                "memory.system": _MEMORY_SYSTEM,
                "op": "put_writes",
                "thread_id": tid,
                "task_id": task_id,
                "writes": jsonable(list(writes)),
            },
            session_id=tid,
        )

    def delete_thread(self, thread_id: str) -> None:
        self._inner.delete_thread(thread_id)
        self._sensor.record(
            EventType.MEMORY_DELETE,
            lambda: {
                "memory.system": _MEMORY_SYSTEM,
                "op": "delete_thread",
                "thread_id": thread_id,
            },
            session_id=thread_id,
        )

    # -- async interface (delegates, records the same events) -----------------

    async def aget_tuple(self, config: dict[str, Any]) -> Any:
        result = await self._inner.aget_tuple(config)
        tid = _thread_id(config)
        self._sensor.record(
            EventType.MEMORY_READ,
            lambda: {
                "memory.system": _MEMORY_SYSTEM,
                "op": "get",
                "thread_id": tid,
                "found": result is not None,
                "checkpoint_id": _thread_safe_checkpoint_id(result),
            },
            session_id=tid,
        )
        return result

    async def aput(
        self,
        config: dict[str, Any],
        checkpoint: dict[str, Any],
        metadata: dict[str, Any],
        new_versions: dict[str, Any],
    ) -> dict[str, Any]:
        result = await self._inner.aput(config, checkpoint, metadata, new_versions)
        tid = _thread_id(config)
        self._sensor.record(
            EventType.MEMORY_WRITE,
            lambda: {
                "memory.system": _MEMORY_SYSTEM,
                "op": "put",
                "thread_id": tid,
                "checkpoint_id": checkpoint.get("id"),
                "checkpoint_ts": checkpoint.get("ts"),
                "channel_values": jsonable(checkpoint.get("channel_values")),
                "metadata": jsonable(metadata),
            },
            session_id=tid,
        )
        return result

    async def adelete_thread(self, thread_id: str) -> None:
        await self._inner.adelete_thread(thread_id)
        self._sensor.record(
            EventType.MEMORY_DELETE,
            lambda: {
                "memory.system": _MEMORY_SYSTEM,
                "op": "delete_thread",
                "thread_id": thread_id,
            },
            session_id=thread_id,
        )


def _thread_safe_checkpoint_id(checkpoint_tuple: Any) -> str | None:
    try:
        return checkpoint_tuple.checkpoint.get("id") if checkpoint_tuple else None
    except Exception:
        return None
