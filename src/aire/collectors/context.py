"""Session/trace attribution for collectors.

The Anthropic API has no session concept, so the host application declares
which session an interaction belongs to via a context manager (works across
threads and asyncio tasks — it's a ContextVar):

    with aire.collectors.session("user-42-conversation-7"):
        client.messages.create(...)

FastAPI apps typically wrap this around request handling using the request's
conversation id.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

_session_id: ContextVar[str | None] = ContextVar("aire_session_id", default=None)
_trace_id: ContextVar[str | None] = ContextVar("aire_trace_id", default=None)


def current_session_id() -> str | None:
    return _session_id.get()


def current_trace_id() -> str | None:
    return _trace_id.get()


@contextmanager
def session(session_id: str, trace_id: str | None = None) -> Iterator[None]:
    """Attribute all events recorded inside this block to ``session_id``."""
    token_s = _session_id.set(session_id)
    token_t = _trace_id.set(trace_id)
    try:
        yield
    finally:
        _session_id.reset(token_s)
        _trace_id.reset(token_t)
