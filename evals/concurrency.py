"""Evidence-store latency under concurrent writers, and per-call sensor overhead.

Two questions a pilot's operators ask before instrumenting anything:

1. **What does recording cost the host?** ``measure_call_overhead`` times an
   instrumented client call against the same call uninstrumented (a fake
   client that does no work, so the difference is AIRE's alone).
2. **What happens when several workers record at once?** A multi-worker app
   server gives each process its own store connection, all writing to one
   file. ``measure_concurrent_writers`` runs W writer *processes* appending as
   fast as they can, which is a stress upper bound: a real application waits
   on an LLM call between events. It reports the latency distribution, write
   failures (the sensor would record those as dropped events instead of
   raising), throughput, and whether the chain verifies with the expected
   event count afterwards.

Numbers depend on the machine and disk; the run records both.
"""

from __future__ import annotations

import multiprocessing as mp
import os
import platform
import sqlite3
import tempfile
import time
from pathlib import Path
from time import perf_counter

from aire.core.events import EventType
from aire.store import EvidenceStore
from evals.metrics import LatencySamples

# ~1 KB of prompt text: the order of size of a real request event.
_PROMPT = ("Summarise the maintenance log for line 4 and list open work orders. " * 15)[:1000]


def _writer(path: str, writer_id: int, n: int, start_at: float) -> tuple[list[float], int]:
    store = EvidenceStore(path)
    samples, failures = [], 0
    while time.time() < start_at:  # start all writers together so they contend
        time.sleep(0.001)
    try:
        for i in range(n):
            started = perf_counter()
            try:
                store.append(
                    session_id=f"w{writer_id}",
                    app="eval.concurrency",
                    event_type=EventType.LLM_REQUEST,
                    payload={"i": i, "messages": [{"role": "user", "content": _PROMPT}]},
                )
            except sqlite3.OperationalError:
                failures += 1  # the sensor swallows this and counts a dropped event
            samples.append((perf_counter() - started) * 1000)
    finally:
        store.close()
    return samples, failures


def measure_concurrent_writers(
    writers: tuple[int, ...] = (1, 2, 4, 8), events_per_writer: int = 500
) -> dict:
    ctx = mp.get_context("spawn")
    results = {}
    for w in writers:
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "concurrency.db")
            EvidenceStore(path).close()  # create schema before writers race
            start_at = time.time() + 1.5
            wall_started = perf_counter()
            with ctx.Pool(w) as pool:
                outcomes = pool.starmap(
                    _writer, [(path, i, events_per_writer, start_at) for i in range(w)]
                )
            wall_s = perf_counter() - wall_started - max(0.0, start_at - time.time())
            latency = LatencySamples()
            failures = 0
            for samples, failed in outcomes:
                for s in samples:
                    latency.record(s)
                failures += failed
            store = EvidenceStore(path, read_only=True)
            verification = store.verify()
            store.close()
            expected = w * events_per_writer - failures
            results[str(w)] = {
                "writers": w,
                "events_attempted": w * events_per_writer,
                "write_failures": failures,
                "chain_ok": verification.ok and verification.checked == expected,
                "append_latency": latency.as_dict(),
                "throughput_events_per_s": round(expected / wall_s, 1) if wall_s > 0 else None,
            }
    return results


class _FakeCompletions:
    def create(self, **kwargs):
        message = type("M", (), {"role": "assistant", "content": "ok", "tool_calls": None})()
        choice = type("C", (), {"message": message, "finish_reason": "stop", "index": 0})()
        usage = type("U", (), {"prompt_tokens": 250, "completion_tokens": 1})()
        return type("R", (), {"id": "r1", "model": "fake", "choices": [choice], "usage": usage})()


class _FakeClient:
    def __init__(self) -> None:
        self.chat = type("Chat", (), {"completions": _FakeCompletions()})()


def measure_call_overhead(n: int = 1000) -> dict:
    """Instrumented minus bare call time, per call (request + response events)."""
    from aire.collectors.openai_sdk import instrument

    messages = [{"role": "user", "content": _PROMPT}]
    bare_client, bare = _FakeClient(), LatencySamples()
    for _ in range(n):
        started = perf_counter()
        bare_client.chat.completions.create(model="fake", messages=messages)
        bare.record((perf_counter() - started) * 1000)

    with tempfile.TemporaryDirectory() as tmp:
        store = EvidenceStore(Path(tmp) / "overhead.db")
        client, instrumented = instrument(_FakeClient(), store=store, app="eval"), LatencySamples()
        try:
            for _ in range(n):
                started = perf_counter()
                client.chat.completions.create(model="fake", messages=messages)
                instrumented.record((perf_counter() - started) * 1000)
            events = sum(1 for _ in store.events())
        finally:
            store.close()
    return {
        "calls": n,
        "events_recorded": events,
        "bare_call": bare.as_dict(),
        "instrumented_call": instrumented.as_dict(),
    }


def environment() -> dict:
    return {
        "cpus": os.cpu_count(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "sqlite": sqlite3.sqlite_version,
    }
