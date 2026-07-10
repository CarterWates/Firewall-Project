from __future__ import annotations

from pathlib import Path

import typer
from pydantic import ValidationError

from firewall_monitor.core.loader import PolicyLoadError, load_policy_file
from firewall_monitor.firewall.nftables import render_nftables_ruleset
from firewall_monitor.firewall.safety import (
    ApplyPlan,
    FirewallEnvironment,
    build_apply_plan,
    inspect_environment,
)

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
def status() -> None:
    """Report local firewall safety facts without changing system state."""

    environment = inspect_environment()
    typer.echo("Firewall monitor status")
    typer.echo(f"Platform: {environment.platform}")
    typer.echo(f"Linux host: {_yes_no(environment.is_linux)}")
    typer.echo(f"Root privileges: {_yes_no(environment.is_root)}")
    typer.echo(f"nftables binary: {environment.nft_path or 'not found'}")
    typer.echo(f"Remote SSH session: {_yes_no(environment.in_remote_ssh_session)}")


@app.command()
def apply(policy_file: Path, dry_run: bool = typer.Option(False, "--dry-run")) -> None:
    """Preview generated rules; real firewall application is not implemented yet."""

    if not dry_run:
        typer.echo("Refusing to apply rules: this milestone only supports --dry-run.")
        raise typer.Exit(1)

    try:
        policy = load_policy_file(policy_file)
    except (PolicyLoadError, ValidationError) as exc:
        typer.echo(f"Policy is invalid: {exc}")
        raise typer.Exit(1) from exc

    environment = inspect_environment()
    plan = build_apply_plan(policy, environment)
    typer.echo("Dry run only. No firewall commands were executed.\n")
    _print_safety_plan(environment, plan)
    typer.echo()
    typer.echo(render_nftables_ruleset(policy), nl=False)


def _print_safety_plan(environment: FirewallEnvironment, plan: ApplyPlan) -> None:
    typer.echo("Safety plan")
    typer.echo(f"- Platform: {environment.platform}")
    typer.echo(f"- nftables binary: {environment.nft_path or 'not found'}")
    typer.echo(f"- Root privileges: {_yes_no(environment.is_root)}")
    typer.echo(f"- Remote SSH session: {_yes_no(environment.in_remote_ssh_session)}")
    typer.echo(f"- Explicit SSH allow rule: {_yes_no(plan.has_ssh_accept_rule)}")

    if plan.blockers:
        typer.echo("- Future real-apply blockers:")
        for blocker in plan.blockers:
            typer.echo(f"  - {blocker}")
    else:
        typer.echo("- Future real-apply blockers: none detected")

    if plan.warnings:
        typer.echo("- Warnings:")
        for warning in plan.warnings:
            typer.echo(f"  - {warning}")
    else:
        typer.echo("- Warnings: none")


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


if __name__ == "__main__":
    app()
