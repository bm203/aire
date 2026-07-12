"""AIRE command-line interface."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

import aire

app = typer.Typer(help="AIRE — AI Runtime Evidence Engine", no_args_is_help=True)


@app.command()
def version() -> None:
    """Print the AIRE version."""
    typer.echo(aire.__version__)


@app.command()
def dashboard(
    db: Annotated[
        Path | None, typer.Argument(help="Path to the evidence store (SQLite file)")
    ] = None,
    host: Annotated[
        str, typer.Option("--host", help="Bind address (localhost only unless you know why)")
    ] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", "-p", help="Port")] = 8787,
    title: Annotated[str, typer.Option("--title")] = "AIRE Audit Report",
    demo: Annotated[
        bool,
        typer.Option("--demo", help="Serve a synthetic populated demo store (needs pii+langgraph)"),
    ] = False,
) -> None:
    """Serve a local, read-only web dashboard over an evidence store.

    Displays the findings, risk, framework citations, and event timeline that
    `aire evaluate` / `aire detect` already recorded — it never writes to the
    store. Binds 127.0.0.1 by default; do not expose it publicly without an
    authenticating reverse proxy. Use `--demo` to build and serve a synthetic
    populated audit for a first look.
    """
    try:
        import uvicorn

        from aire.dashboard import build_app
    except ImportError as exc:
        typer.secho(
            f"error: the dashboard needs the 'dashboard' extra "
            f"(pip install 'aire[dashboard]') — {exc}",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=2) from exc

    if demo:
        import tempfile

        try:
            from aire.dashboard.demo import build_demo_store
        except ImportError as exc:
            typer.secho(f"error: --demo needs extras — {exc}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=2) from exc
        tmp = Path(tempfile.mkdtemp(prefix="aire-demo-"))
        typer.echo("building synthetic demo evidence store…")
        db = build_demo_store(tmp / "demo_evidence.db", tmp / "demo_memory.db")
        title = "AIRE — demo (synthetic data)"
    elif db is None:
        typer.secho("error: pass an evidence DB path, or --demo", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)
    elif not db.exists():
        typer.secho(f"error: no such file: {db}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)

    if host not in ("127.0.0.1", "localhost", "::1"):
        typer.secho(
            f"warning: binding {host} exposes the dashboard beyond localhost — "
            "it has no authentication; put it behind an authenticating proxy.",
            fg=typer.colors.YELLOW,
            err=True,
        )

    typer.secho(f"AIRE dashboard → http://{host}:{port}  (Ctrl-C to stop)", fg=typer.colors.GREEN)
    uvicorn.run(build_app(db, title=title), host=host, port=port, log_level="warning")


@app.command()
def report(
    db: Annotated[Path, typer.Argument(help="Path to the evidence store (SQLite file)")],
    out: Annotated[
        Path | None,
        typer.Option("--out", "-o", help="Output file (.html/.md/.json decides the format)"),
    ] = None,
    fmt: Annotated[
        str | None,
        typer.Option("--format", "-f", help="json | md | html (overrides extension)"),
    ] = None,
    session_id: Annotated[
        str | None, typer.Option("--session", help="Only report on this session")
    ] = None,
    title: Annotated[str, typer.Option("--title")] = "AIRE Audit Report",
) -> None:
    """Generate an audit report from stored evidence.

    Reads the findings and policy results recorded by `aire detect` and
    `aire evaluate`. JSON is canonical; Markdown/HTML are renderings of it.
    Reports may contain sensitive summaries — files are written 0600.
    """
    import os

    from aire.report import build_report, to_html, to_json, to_markdown
    from aire.store import EvidenceStore

    if not db.exists():
        typer.secho(f"error: no such file: {db}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)

    renderers = {"json": to_json, "md": to_markdown, "markdown": to_markdown, "html": to_html}
    chosen = (fmt or (out.suffix.lstrip(".").lower() if out else "md")).lower()
    render = renderers.get(chosen)
    if render is None:
        typer.secho(
            f"error: unknown format {chosen!r} (json|md|html)", fg=typer.colors.RED, err=True
        )
        raise typer.Exit(code=2)

    store = EvidenceStore(db)
    try:
        audit = build_report(store, session_id=session_id, title=title)
    finally:
        store.close()
    output = render(audit)

    if out is None:
        typer.echo(output)
    else:
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(output)
        typer.secho(
            f"wrote {out} — overall risk {audit.overall_risk_level.value.upper()} "
            f"(score {audit.overall_risk_score}), chain "
            f"{'INTACT' if audit.chain.ok else 'BROKEN'}",
            fg=typer.colors.GREEN if audit.chain.ok else typer.colors.RED,
        )
    if not audit.chain.ok:
        raise typer.Exit(code=1)


@app.command()
def mappings(
    fmt: Annotated[str, typer.Option("--format", "-f", help="md | json")] = "md",
) -> None:
    """Print the framework mappings (source of truth for report citations).

    Pipe to a file to (re)generate the public mapping documentation:
    `aire mappings > docs/framework-mappings.md`.
    """
    from aire.mappings import FrameworkMappings

    loaded = FrameworkMappings.load()
    citations = loaded.all_citations()
    if fmt == "json":
        import json as _json

        typer.echo(
            _json.dumps([c.model_dump() for c in citations], indent=2, ensure_ascii=False)
        )
        return
    typer.echo("# Framework mappings")
    typer.echo()
    typer.echo(
        "Citations AIRE's shipped policies and detectors map to. Generated from "
        "`src/aire/mappings/*.yaml` (single source of truth) via `aire mappings` — "
        "do not edit this file by hand."
    )
    current = None
    for c in citations:
        if c.framework != current:
            current = c.framework
            typer.echo(f"\n## {c.framework_name}\n")
            typer.echo("| Control | Title | Reference |")
            typer.echo("|---|---|---|")
        link = f"[link]({c.url})" if c.url else "—"
        typer.echo(f"| `{c.ref}` | {c.title} | {link} |")


@app.command()
def evaluate(
    db: Annotated[Path, typer.Argument(help="Path to the evidence store (SQLite file)")],
    policies: Annotated[
        Path | None,
        typer.Option("--policies", "-p", help="Policy YAML file or directory"),
    ] = None,
    builtin: Annotated[
        bool, typer.Option("--builtin", help="Include AIRE's builtin starter policies")
    ] = False,
    session_id: Annotated[
        str | None, typer.Option("--session", help="Only evaluate this session's events")
    ] = None,
) -> None:
    """Evaluate policies over stored evidence; append results to the chain.

    Fail/warn/error results are recorded per event with evidence pointers; a
    run-summary event proves evaluation coverage. Re-running is idempotent.
    """
    from aire.policy import (
        PolicyEngine,
        PolicyLoadError,
        builtin_policies,
        load_policies,
    )
    from aire.policy.engine import PolicyCompileError
    from aire.store import EvidenceStore

    if not db.exists():
        typer.secho(f"error: no such file: {db}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)
    if policies is None and not builtin:
        typer.secho("error: pass --policies and/or --builtin", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)

    try:
        policy_list = (builtin_policies() if builtin else []) + (
            load_policies(policies) if policies else []
        )
        engine = PolicyEngine(policy_list)
    except (PolicyLoadError, PolicyCompileError) as exc:
        typer.secho(f"policy error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    store = EvidenceStore(db)
    try:
        outcome = engine.run(store, session_id=session_id)
    finally:
        store.close()

    typer.echo(
        f"evaluated {outcome.events_evaluated} event(s) against "
        f"{len(engine.policies)} policy(ies): {outcome.counts or 'nothing applicable'}"
    )
    for event in outcome.recorded:
        p = event.payload
        color = typer.colors.RED if p["verdict"] == "fail" else typer.colors.YELLOW
        typer.secho(
            f"  [{p['verdict'].upper()}] {p['policy_id']} ({p['severity']}) "
            f"session={p['source_session_id']} evidence={p['source_event_id']}",
            fg=color,
        )
        typer.echo(f"         {p['explanation']}")


@app.command()
def verify(
    db: Annotated[Path, typer.Argument(help="Path to the evidence store (SQLite file)")],
) -> None:
    """Verify the integrity of an evidence store's hash chain.

    Exit code 0 if the chain is intact, 1 if tampering or a chain break is
    detected, 2 if the store cannot be opened.
    """
    from aire.store import EvidenceStore

    if not db.exists():
        typer.secho(f"error: no such file: {db}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)

    store = EvidenceStore(db)
    try:
        result = store.verify()
    finally:
        store.close()

    if result.ok:
        typer.secho(f"OK — chain intact, {result.checked} event(s) verified", fg=typer.colors.GREEN)
        return
    typer.secho(
        f"TAMPER DETECTED after {result.checked} intact event(s): "
        f"seq={result.first_bad_seq} event_id={result.first_bad_event_id}\n"
        f"reason: {result.reason}",
        fg=typer.colors.RED,
        err=True,
    )
    raise typer.Exit(code=1)


@app.command()
def detect(
    db: Annotated[Path, typer.Argument(help="Path to the evidence store (SQLite file)")],
    memory_db: Annotated[
        Path | None,
        typer.Option(
            "--memory-db",
            help="LangGraph checkpointer DB — enables the memory retention/deletion control "
            "(opened strictly read-only)",
        ),
    ] = None,
    retention_days: Annotated[
        float | None,
        typer.Option("--retention-days", help="Max allowed memory age for the retention check"),
    ] = None,
    pii: Annotated[
        bool, typer.Option("--pii/--no-pii", help="Run the Presidio PII detector")
    ] = True,
    pii_model: Annotated[
        str, typer.Option("--pii-model", help="spaCy model for Presidio")
    ] = "en_core_web_sm",
    pii_entities: Annotated[
        str | None,
        typer.Option(
            "--pii-entities",
            help="Comma-separated Presidio entity types to detect "
            "(default: PERSON,EMAIL_ADDRESS,PHONE_NUMBER,US_SSN,CREDIT_CARD,IBAN_CODE,IP_ADDRESS)",
        ),
    ] = None,
    session_id: Annotated[
        str | None, typer.Option("--session", help="Only inspect this session's events")
    ] = None,
) -> None:
    """Run detectors over stored evidence; append findings to the chain.

    Always runs prompt-injection and audit-log-completeness detectors. PII
    (Presidio) runs unless --no-pii or the extra isn't installed, over a tuned
    high-signal entity set by default (override with --pii-entities). The deep
    memory retention/deletion control runs when --memory-db is given.
    """
    from aire.detectors import CompletenessDetector, DetectorRunner, PromptInjectionDetector
    from aire.store import EvidenceStore

    if not db.exists():
        typer.secho(f"error: no such file: {db}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)

    detectors = [PromptInjectionDetector(), CompletenessDetector()]

    scanner = None
    if pii:
        try:
            from aire.detectors.pii import PIIDetector, PresidioScanner

            entities = (
                [e.strip() for e in pii_entities.split(",") if e.strip()]
                if pii_entities
                else None
            )
            scanner = PresidioScanner(model=pii_model, entities=entities)
            detectors.append(PIIDetector(scanner=scanner))
        except ImportError:
            typer.secho(
                "note: PII detector skipped — install 'aire[pii]' and a spaCy model",
                fg=typer.colors.YELLOW,
                err=True,
            )

    if memory_db is not None:
        try:
            from aire.detectors.memory_retention import MemoryRetentionControl

            detectors.append(
                MemoryRetentionControl(
                    memory_db, retention_max_days=retention_days, pii_scanner=scanner
                )
            )
        except ImportError:
            typer.secho(
                "note: memory control skipped — install 'aire[langgraph]'",
                fg=typer.colors.YELLOW,
                err=True,
            )

    store = EvidenceStore(db)
    try:
        outcome = DetectorRunner(detectors).run(store, session_id=session_id)
    finally:
        store.close()

    typer.echo(
        f"scanned {outcome.events_scanned} event(s) with "
        f"{len(detectors)} detector(s): {outcome.counts or 'no findings'}"
    )
    palette = {
        "critical": typer.colors.BRIGHT_RED,
        "high": typer.colors.RED,
        "medium": typer.colors.YELLOW,
        "low": typer.colors.CYAN,
        "info": typer.colors.WHITE,
    }
    for event in outcome.recorded:
        p = event.payload
        typer.secho(
            f"  [{p['severity'].upper()}] {p['detector_id']} session={p['session_id']}",
            fg=palette.get(p["severity"], typer.colors.WHITE),
        )
        typer.echo(f"         {p['summary']}")
