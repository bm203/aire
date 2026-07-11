"""The read-only dashboard FastAPI app and its hardened rendering."""

from __future__ import annotations

from pathlib import Path

try:
    from fastapi import FastAPI, Request, Response
    from fastapi.responses import HTMLResponse
    from fastapi.staticfiles import StaticFiles
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "the dashboard requires the 'dashboard' extra: pip install 'aire[dashboard]'"
    ) from exc

from jinja2 import Environment, FileSystemLoader

from aire.report.build import build_report
from aire.report.render import to_json
from aire.store import EvidenceStore

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

    @app.get("/api/report.json")
    def report_json() -> Response:
        return Response(to_json(_report()), media_type="application/json")

    return app
