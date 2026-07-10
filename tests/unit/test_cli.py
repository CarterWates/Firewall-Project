from pathlib import Path

from typer.testing import CliRunner

from firewall_monitor.cli.main import app


def write_policy(path: Path) -> None:
    path.write_text(
        """
version: 1
default_policy:
  input: drop
  output: accept
  forward: drop
rules:
  - name: allow-docs-ssh
    direction: input
    action: accept
    protocol: tcp
    source: 192.0.2.0/24
    destination_port: 22
""".strip(),
        encoding="utf-8",
    )


def test_validate_command_reports_valid_policy(tmp_path: Path) -> None:
    policy_path = tmp_path / "firewall.yaml"
    write_policy(policy_path)
    runner = CliRunner()

    result = runner.invoke(app, ["validate", str(policy_path)])

    assert result.exit_code == 0
    assert "Policy is valid" in result.stdout


def test_generate_command_prints_ruleset(tmp_path: Path) -> None:
    policy_path = tmp_path / "firewall.yaml"
    write_policy(policy_path)
    runner = CliRunner()

    result = runner.invoke(app, ["generate", str(policy_path)])

    assert result.exit_code == 0
    assert "table inet firewall_monitor" in result.stdout


def test_apply_requires_dry_run(tmp_path: Path) -> None:
    policy_path = tmp_path / "firewall.yaml"
    write_policy(policy_path)
    runner = CliRunner()

    result = runner.invoke(app, ["apply", str(policy_path)])

    assert result.exit_code != 0
    assert "phase one only supports --dry-run" in result.stdout


def test_apply_dry_run_prints_ruleset_without_applying(tmp_path: Path) -> None:
    policy_path = tmp_path / "firewall.yaml"
    write_policy(policy_path)
    runner = CliRunner()

    result = runner.invoke(app, ["apply", str(policy_path), "--dry-run"])

    assert result.exit_code == 0
    assert "Dry run only" in result.stdout
    assert "table inet firewall_monitor" in result.stdout
