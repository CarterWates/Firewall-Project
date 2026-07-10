from __future__ import annotations

from pathlib import Path

import typer
from pydantic import ValidationError

from firewall_monitor.core.loader import PolicyLoadError, load_policy_file
from firewall_monitor.firewall.nftables import render_nftables_ruleset

app = typer.Typer(help="Validate and generate safe Linux firewall policy rulesets.")


@app.command()
def validate(policy_file: Path) -> None:
    """Validate a YAML firewall policy file."""

    try:
        policy = load_policy_file(policy_file)
    except (PolicyLoadError, ValidationError) as exc:
        typer.echo(f"Policy is invalid: {exc}")
        raise typer.Exit(1) from exc

    typer.echo(f"Policy is valid: {len(policy.rules)} rule(s)")


@app.command()
def generate(policy_file: Path) -> None:
    """Print nftables ruleset text for a validated policy."""

    try:
        policy = load_policy_file(policy_file)
    except (PolicyLoadError, ValidationError) as exc:
        typer.echo(f"Policy is invalid: {exc}")
        raise typer.Exit(1) from exc

    typer.echo(render_nftables_ruleset(policy), nl=False)


@app.command()
def apply(policy_file: Path, dry_run: bool = typer.Option(False, "--dry-run")) -> None:
    """Preview generated rules; real firewall application is not implemented yet."""

    if not dry_run:
        typer.echo("Refusing to apply rules: phase one only supports --dry-run.")
        raise typer.Exit(1)

    try:
        policy = load_policy_file(policy_file)
    except (PolicyLoadError, ValidationError) as exc:
        typer.echo(f"Policy is invalid: {exc}")
        raise typer.Exit(1) from exc

    typer.echo("Dry run only. No firewall commands were executed.\n")
    typer.echo(render_nftables_ruleset(policy), nl=False)


if __name__ == "__main__":
    app()
