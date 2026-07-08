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
