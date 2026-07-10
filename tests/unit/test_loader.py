from pathlib import Path

import pytest
from pydantic import ValidationError

from firewall_monitor.core.loader import PolicyLoadError, load_policy_file


def test_loads_policy_from_yaml(tmp_path: Path) -> None:
    policy_path = tmp_path / "firewall.yaml"
    policy_path.write_text(
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

    policy = load_policy_file(policy_path)

    assert policy.rules[0].name == "allow-docs-ssh"


def test_reports_missing_policy_file(tmp_path: Path) -> None:
    with pytest.raises(PolicyLoadError, match="does not exist"):
        load_policy_file(tmp_path / "missing.yaml")


def test_rejects_empty_yaml_file(tmp_path: Path) -> None:
    policy_path = tmp_path / "empty.yaml"
    policy_path.write_text("", encoding="utf-8")

    with pytest.raises(PolicyLoadError, match="empty"):
        load_policy_file(policy_path)


def test_preserves_validation_errors_for_invalid_yaml_policy(tmp_path: Path) -> None:
    policy_path = tmp_path / "invalid.yaml"
    policy_path.write_text(
        """
version: 1
default_policy:
  input: drop
  output: accept
  forward: drop
rules:
  - name: bad-port
    direction: input
    action: accept
    protocol: tcp
    destination_port: 70000
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(ValidationError):
        load_policy_file(policy_path)
