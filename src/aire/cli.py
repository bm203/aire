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
