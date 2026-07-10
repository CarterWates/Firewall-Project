from datetime import UTC, datetime
from pathlib import Path

from typer.testing import CliRunner

from firewall_monitor.cli.main import app
from firewall_monitor.database.events import FirewallEventRepository
from firewall_monitor.database.session import create_sqlite_engine, init_database
from firewall_monitor.monitoring.events import FirewallEvent


def test_detect_scan_reports_suspicious_source(tmp_path: Path) -> None:
    db_path = tmp_path / "events.sqlite3"
    engine = create_sqlite_engine(db_path)
    init_database(engine)
    repository = FirewallEventRepository(engine)
    occurred_at = datetime.now(UTC)
    for _ in range(3):
        repository.add(
            FirewallEvent(
                occurred_at=occurred_at,
                action="blocked",
                rule_name="block-telnet",
                source_ip="203.0.113.10",
                destination_ip="192.0.2.20",
                protocol="tcp",
                destination_port=23,
                input_interface="eth0",
                output_interface=None,
                raw_message="test",
            )
        )
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "detect",
            "scan",
            "--db",
            str(db_path),
            "--min-attempts",
            "3",
            "--window-minutes",
            "60",
        ],
    )

    assert result.exit_code == 0
    assert "Suspicious source detected" in result.stdout
    assert "203.0.113.10" in result.stdout
    assert "Dry run only" in result.stdout
