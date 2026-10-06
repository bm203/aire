"""Background evidence writer: keeps all I/O off the host's threads.

A collector's ``Sensor`` builds the payload on the host thread (so the evidence
captures the call as it happened, and the host can mutate its objects safely
afterwards), then hands the finished event to a bounded in-memory queue. One
writer thread per process and store drains the queue into SQLite. The host
thread never waits on the database:

* **Fail-open, bounded.** ``submit`` never blocks. A full queue is a counted
  drop that later becomes a ``sensor.dropped`` event, so gaps in the evidence
  stay visible (the completeness detector turns them into findings).
* **Fair across processes.** The writer takes a kernel file lock
  (``<store>.lock``) around each append, so writers in different worker
  processes queue fairly instead of SQLite's polling busy handler, which can
  starve a writer for seconds. Waiting here costs the host nothing.
* **Fork-safe.** SQLite connections must not cross ``fork()``. Writers are
  keyed by process id and open their own connection in their own thread, so
  a forked worker starts a fresh writer.
* **Durability trade-off.** Events still in the queue are lost if the process
  is killed hard. Normal interpreter shutdown flushes the queue (bounded by
  ``SHUTDOWN_FLUSH_SECONDS``).

Reads made in the same process (``EvidenceStore.events()``, ``verify()``, ...)
first wait briefly for that process's pending writes, so code that writes and
then reads in one process sees its own events.
"""

from __future__ import annotations

import atexit
import os
import queue
import threading
import time
import weakref
from typing import Any

from aire.core.events import EventType
from aire.store import EvidenceStore
from aire.store import sqlite as _sqlite

try:  # POSIX only; elsewhere the writer relies on SQLite's own locking
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

DEFAULT_MAX_QUEUE = 10_000
READ_FLUSH_SECONDS = 5.0
SHUTDOWN_FLUSH_SECONDS = 5.0
_STOP = object()


class BackgroundWriter:
    def __init__(self, path: str, max_queue: int = DEFAULT_MAX_QUEUE) -> None:
        self.path = path
        self.failed = 0  # appends that raised inside the writer
        self._queue: queue.Queue = queue.Queue(maxsize=max_queue)
        self._thread = threading.Thread(target=self._run, name="aire-evidence-writer",
                                        daemon=True)
        self._thread.start()

    @property
    def thread(self) -> threading.Thread:
        return self._thread

    def submit(self, item: dict[str, Any]) -> bool:
        """Queue one event for writing. Never blocks; False means dropped."""
        try:
            self._queue.put_nowait(item)
        except queue.Full:
            return False
        return True

    def flush(self, timeout: float) -> bool:
        """Wait until everything queued so far has been written (or failed)."""
        if threading.current_thread() is self._thread or not self._thread.is_alive():
            return self._queue.unfinished_tasks == 0
        deadline = time.monotonic() + timeout
        with self._queue.all_tasks_done:
            while self._queue.unfinished_tasks:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._queue.all_tasks_done.wait(remaining)
        return True

    def stop(self, timeout: float) -> None:
        self.flush(timeout)
        try:
            self._queue.put_nowait(_STOP)
        except queue.Full:
            return
        self._thread.join(timeout)

    def _run(self) -> None:
        store = EvidenceStore(self.path)
        lock_fd = os.open(self.path + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            while True:
                item = self._queue.get()
                try:
                    if item is _STOP:
                        return
                    self._append(store, lock_fd, item)
                finally:
                    self._queue.task_done()
        finally:
            store.close()
            os.close(lock_fd)

    def _append(self, store: EvidenceStore, lock_fd: int, item: dict[str, Any]) -> None:
        try:
            if fcntl is not None:
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
            try:
                if self.failed:
                    store.append(session_id=item["session_id"], app=item["app"],
                                 event_type=EventType.SENSOR_DROPPED,
                                 payload={"count": self.failed})
                    self.failed = 0
                store.append(**item)
            finally:
                if fcntl is not None:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
        except Exception:
            self.failed += 1  # recorded as sensor.dropped on the next successful write


_writers: dict[tuple[int, str], BackgroundWriter] = {}
_registry_lock = threading.Lock()
# Sensors with a pending drop count report it at shutdown (see Sensor.report_drops).
_drop_reporters: weakref.WeakSet = weakref.WeakSet()


def register_drop_reporter(sensor: Any) -> None:
    _drop_reporters.add(sensor)


def _key(path: str | os.PathLike) -> tuple[int, str]:
    return os.getpid(), os.path.realpath(path)


def get_writer(path: str | os.PathLike, max_queue: int = DEFAULT_MAX_QUEUE) -> BackgroundWriter:
    key = _key(path)
    with _registry_lock:
        writer = _writers.get(key)
        if writer is None or not writer.thread.is_alive():
            writer = _writers[key] = BackgroundWriter(key[1], max_queue)
        return writer


def flush(path: str | os.PathLike, timeout: float = READ_FLUSH_SECONDS) -> bool:
    """Wait for this process's pending writes to ``path``. True if all written."""
    writer = _writers.get(_key(path))
    return True if writer is None else writer.flush(timeout)


def flush_all(timeout: float = SHUTDOWN_FLUSH_SECONDS) -> bool:
    pid = os.getpid()
    deadline = time.monotonic() + timeout
    done = True
    for (owner, _), writer in list(_writers.items()):
        if owner == pid:
            done &= writer.flush(max(0.0, deadline - time.monotonic()))
    return done


def _before_read(path: str) -> None:
    flush(path)


def _after_fork_in_child() -> None:
    global _registry_lock
    _registry_lock = threading.Lock()  # a parent thread may have held it at fork time


def _shutdown() -> None:
    pid = os.getpid()
    deadline = time.monotonic() + SHUTDOWN_FLUSH_SECONDS
    # Drain first: a pending drop notice needs room in the queue, and the queue
    # is typically full exactly when drops happened.
    flush_all(SHUTDOWN_FLUSH_SECONDS / 2)
    for sensor in list(_drop_reporters):
        try:
            sensor.report_drops()
        except Exception:
            pass
    for (owner, _), writer in list(_writers.items()):
        if owner == pid:
            writer.stop(max(0.0, deadline - time.monotonic()))


_sqlite.register_read_hook(_before_read)
atexit.register(_shutdown)
if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)
