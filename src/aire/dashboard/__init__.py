"""Local, read-only audit dashboard for AIRE.

A minimal browser view over the evidence a store already contains — the
``AuditReport`` (findings, risk, chain status, framework citations) plus the
raw event timeline. It adds **no detection logic**; it renders what
``aire evaluate`` / ``aire detect`` already recorded.

Security posture (carried from the report renderer):

- **Read-only** — the store is opened OS-level read-only; the dashboard never
  writes. No POST routes.
- **Localhost only** — binds 127.0.0.1 by default; no authentication (it is a
  single-user local tool). Do not expose it publicly without an
  authenticating reverse proxy.
- **No external resources, no scripts** — inline/same-origin CSS only,
  enforced by a strict Content-Security-Policy (no ``script-src``).
- **All content autoescaped** — event payloads carry untrusted prompt/PII
  text; rendering is size-bounded and HTML-escaped.

Requires the ``dashboard`` extra: ``pip install 'aire[dashboard]'``.
"""

from aire.dashboard.app import build_app

__all__ = ["build_app"]
