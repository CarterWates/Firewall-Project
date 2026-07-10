from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from firewall_monitor.api.app import create_app
from firewall_monitor.core.loader import PolicyLoadError, load_policy_file
from firewall_monitor.database.events import FirewallEventRepository
from firewall_monitor.database.session import create_sqlite_engine, init_database
from firewall_monitor.detection.blocking import build_temporary_block_plan
from firewall_monitor.detection.suspicious import find_suspicious_sources
from firewall_monitor.firewall.nftables import render_nftables_ruleset
from firewall_monitor.firewall.safety import (
    ApplyPlan,
    FirewallEnvironment,
    build_apply_plan,
    inspect_environment,
)
from firewall_monitor.monitoring.events import parse_firewall_log_line

app = typer.Typer(help="Validate and generate safe Linux firewall policy rulesets.")
events_app = typer.Typer(help="Ingest and inspect firewall log events.")
detect_app = typer.Typer(help="Detect repeated suspicious firewall events.")
app.add_typer(events_app, name="events")
app.add_typer(detect_app, name="detect")

DEFAULT_DB_PATH = Path("data/firewall-monitor.sqlite3")


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
def serve(
    db_path: Annotated[
        Path,
        typer.Option("--db", help="SQLite database path."),
    ] = DEFAULT_DB_PATH,
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port", min=1, max=65535),
) -> None:
    """Run the local FastAPI dashboard."""

    import uvicorn

    uvicorn.run(create_app(db_path), host=host, port=port)


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


@events_app.command("ingest")
def ingest_events(
    log_file: Path,
    db_path: Annotated[
        Path,
        typer.Option("--db", help="SQLite database path."),
    ] = DEFAULT_DB_PATH,
) -> None:
    """Parse a log file and store firewall-monitor events."""

    if not log_file.exists():
        typer.echo(f"Log file does not exist: {log_file}")
        raise typer.Exit(1)

    engine = create_sqlite_engine(db_path)
    init_database(engine)
    repository = FirewallEventRepository(engine)
    imported = 0

    for line in log_file.read_text(encoding="utf-8").splitlines():
        event = parse_firewall_log_line(line)
        if event is None:
            continue
        repository.add(event)
        imported += 1

    typer.echo(f"Imported {imported} event(s)")


@events_app.command("list")
def list_events(
    db_path: Annotated[
        Path,
        typer.Option("--db", help="SQLite database path."),
    ] = DEFAULT_DB_PATH,
    limit: int = typer.Option(20, "--limit", min=1, max=200),
) -> None:
    """List recent stored firewall events."""

    engine = create_sqlite_engine(db_path)
    init_database(engine)
    repository = FirewallEventRepository(engine)
    events = repository.list_recent(limit=limit)
    if not events:
        typer.echo("No firewall events found.")
        return

    for event in events:
        destination = event.destination_ip
        if event.destination_port is not None:
            destination = f"{destination}:{event.destination_port}"
        typer.echo(
            f"{event.occurred_at.isoformat()} "
            f"{event.action} {event.protocol} "
            f"{event.source_ip} -> {destination} "
            f"rule={event.rule_name}"
        )


@detect_app.command("scan")
def scan_events(
    db_path: Annotated[
        Path,
        typer.Option("--db", help="SQLite database path."),
    ] = DEFAULT_DB_PATH,
    min_attempts: int = typer.Option(5, "--min-attempts", min=2, max=1000),
    window_minutes: int = typer.Option(15, "--window-minutes", min=1, max=1440),
    block_minutes: int = typer.Option(30, "--block-minutes", min=1, max=1440),
) -> None:
    """Find repeated blocked sources and print dry-run block recommendations."""

    engine = create_sqlite_engine(db_path)
    init_database(engine)
    repository = FirewallEventRepository(engine)
    now = datetime.now(UTC)
    since = now - timedelta(minutes=window_minutes)
    findings = find_suspicious_sources(
        repository.list_since(since),
        min_attempts=min_attempts,
    )

    if not findings:
        typer.echo("No suspicious sources found.")
        return

    typer.echo("Dry run only. No firewall commands were executed.")
    for finding in findings:
        block_plan = build_temporary_block_plan(
            finding.source_ip,
            now,
            duration_minutes=block_minutes,
        )
        typer.echo(
            "Suspicious source detected: "
            f"{finding.source_ip} "
            f"attempts={finding.attempt_count} "
            f"first_seen={finding.first_seen.isoformat()} "
            f"last_seen={finding.last_seen.isoformat()}"
        )
        typer.echo(f"Recommended temporary block: nft {block_plan.nft_rule}")


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
