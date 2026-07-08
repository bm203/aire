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
    session_id: Annotated[
        str | None, typer.Option("--session", help="Only inspect this session's events")
    ] = None,
) -> None:
    """Run detectors over stored evidence; append findings to the chain.

    Always runs prompt-injection and audit-log-completeness detectors. PII
    (Presidio) runs unless --no-pii or the extra isn't installed. The deep
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

            scanner = PresidioScanner(model=pii_model)
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
