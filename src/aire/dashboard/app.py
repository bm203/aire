"""The read-only dashboard FastAPI app and its hardened rendering."""

from __future__ import annotations

import json
from pathlib import Path

try:
    from fastapi import FastAPI, HTTPException, Query, Request, Response
    from fastapi.responses import HTMLResponse
    from fastapi.staticfiles import StaticFiles
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "the dashboard requires the 'dashboard' extra: pip install 'aire[dashboard]'"
    ) from exc

from jinja2 import Environment, FileSystemLoader

from aire.core.events import AuditEvent, EventType
from aire.report.build import build_report
from aire.report.render import to_json
from aire.store import EvidenceStore

# Findings/policy results are shown in the findings table, not the raw timeline.
_TIMELINE_EXCLUDE = frozenset({EventType.FINDING, EventType.POLICY_RESULT})

# Severity ordering for the triage view + the filter chips shown in the UI.
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_SEVERITIES = ["critical", "high", "medium", "low", "info"]

_TEMPLATES = Path(__file__).parent / "templates"
_STATIC = Path(__file__).parent / "static"

# Strict CSP: no script-src at all (scripts can never run), styles/images only
# from same origin (plus data: images). Defense-in-depth over autoescaping.
_CSP = (
    "default-src 'none'; style-src 'self'; img-src 'self' data:; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)

# Cap how much of a raw event payload the timeline/event views render — event
# payloads hold prompts/PII and can be large; never dump an unbounded blob.
MAX_PAYLOAD_CHARS = 20_000


def _render_env() -> Environment:
    # autoescape forced on — all rendered content (prompt excerpts, session
    # ids) is untrusted. Mirrors aire.report.render.
    return Environment(loader=FileSystemLoader(str(_TEMPLATES)), autoescape=True)


def _event_view(event: AuditEvent) -> dict:
    """Render-safe view of one event with a size-bounded payload."""
    payload = json.dumps(event.payload, indent=2, ensure_ascii=False, default=str)
    truncated = len(payload) > MAX_PAYLOAD_CHARS
    if truncated:
        payload = payload[:MAX_PAYLOAD_CHARS] + "\n… (truncated — full payload in the store)"
    return {
        "event_id": event.event_id,
        "ts": event.ts,
        "session_id": event.session_id,
        "event_type": event.event_type.value,
        "app": event.app,
        "hash": event.hash,
        "prev_hash": event.prev_hash,
        "payload": payload,
        "truncated": truncated,
    }


def build_app(evidence_db: str | Path, *, title: str = "AIRE Audit Report") -> FastAPI:
    """Build the read-only dashboard app over one evidence store."""
    evidence_db = Path(evidence_db)
    env = _render_env()

    app = FastAPI(
        title="AIRE audit dashboard",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")

    @app.middleware("http")
    async def _security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = _CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    def _report(session_id: str | None = None):
        # Fresh read-only handle per request — the store is never mutated.
        store = EvidenceStore(evidence_db, read_only=True)
        try:
            return build_report(store, session_id=session_id, title=title)
        finally:
            store.close()

    def _html(template: str, **ctx) -> HTMLResponse:
        return HTMLResponse(env.get_template(template).render(**ctx))

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/", response_class=HTMLResponse)
    def overview() -> HTMLResponse:
        return _html("overview.html.j2", report=_report())

    @app.get("/session", response_class=HTMLResponse)
    def session_view(session_id: str = Query(alias="id")) -> HTMLResponse:
        report = _report(session_id=session_id)
        session = report.sessions[0] if report.sessions else None
        store = EvidenceStore(evidence_db, read_only=True)
        try:
            events = [
                _event_view(e)
                for e in store.events(session_id=session_id)
                if e.event_type not in _TIMELINE_EXCLUDE
            ]
        finally:
            store.close()
        return _html(
            "session.html.j2",
            report=report,
            session=session,
            session_id=session_id,
            events=events,
        )

    @app.get("/event", response_class=HTMLResponse)
    def event_view(event_id: str = Query(alias="id")) -> HTMLResponse:
        store = EvidenceStore(evidence_db, read_only=True)
        try:
            event = store.get_event(event_id)
        finally:
            store.close()
        if event is None:
            raise HTTPException(status_code=404, detail="event not found")
        return _html("event.html.j2", event=_event_view(event), max_chars=MAX_PAYLOAD_CHARS)

    @app.get("/findings", response_class=HTMLResponse)
    def findings_view(severity: str | None = Query(default=None)) -> HTMLResponse:
        report = _report()
        findings = [f for s in report.sessions for f in s.findings]
        if severity:
            findings = [f for f in findings if f.severity.value == severity]
        findings.sort(key=lambda f: (-_SEV_RANK.get(f.severity.value, 0), f.ts))
        return _html(
            "findings.html.j2",
            report=report,
            findings=findings,
            severity=severity,
            severities=_SEVERITIES,
        )

    @app.get("/api/report.json")
    def report_json() -> Response:
        return Response(to_json(_report()), media_type="application/json")

    return app
