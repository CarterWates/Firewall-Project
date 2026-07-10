from pathlib import Path

from typer.testing import CliRunner

from firewall_monitor.cli.main import app


def test_events_ingest_and_list(tmp_path: Path) -> None:
    db_path = tmp_path / "events.sqlite3"
    log_path = tmp_path / "firewall.log"
    log_path.write_text(
        "\n".join(
            [
                "ordinary kernel line",
                "firewall-monitor block-telnet: IN=eth0 OUT= "
                "SRC=203.0.113.10 DST=192.0.2.20 PROTO=TCP DPT=23",
            ]
        ),
        encoding="utf-8",
    )
    runner = CliRunner()

    ingest_result = runner.invoke(
        app,
        ["events", "ingest", str(log_path), "--db", str(db_path)],
    )
    list_result = runner.invoke(
        app,
        ["events", "list", "--db", str(db_path)],
    )

    assert ingest_result.exit_code == 0
    assert "Imported 1 event(s)" in ingest_result.stdout
    assert list_result.exit_code == 0
    assert "block-telnet" in list_result.stdout
    assert "203.0.113.10" in list_result.stdout
