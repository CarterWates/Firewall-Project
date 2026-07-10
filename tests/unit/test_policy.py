import pytest
from pydantic import ValidationError

from firewall_monitor.core.policy import FirewallPolicy


def valid_policy_data() -> dict[str, object]:
    return {
        "version": 1,
        "default_policy": {"input": "drop", "output": "accept", "forward": "drop"},
        "rules": [
            {
                "name": "allow-docs-ssh",
                "direction": "input",
                "action": "accept",
                "protocol": "tcp",
                "source": "192.0.2.0/24",
                "destination_port": 22,
                "connection_state": ["established", "related", "new"],
            },
            {
                "name": "block-telnet",
                "direction": "input",
                "action": "drop",
                "protocol": "tcp",
                "destination_port": 23,
                "log": True,
            },
        ],
    }


def test_accepts_valid_ipv4_policy() -> None:
    policy = FirewallPolicy.model_validate(valid_policy_data())

    assert policy.version == 1
    assert policy.default_policy.input == "drop"
    assert policy.rules[0].source == "192.0.2.0/24"


def test_rejects_invalid_default_policy() -> None:
    data = valid_policy_data()
    data["default_policy"] = {"input": "allow", "output": "accept", "forward": "drop"}

    with pytest.raises(ValidationError, match="Input should be"):
        FirewallPolicy.model_validate(data)


def test_rejects_invalid_port_value() -> None:
    data = valid_policy_data()
    rules = data["rules"]
    assert isinstance(rules, list)
    rules[0]["destination_port"] = 70000

    with pytest.raises(ValidationError, match="less than or equal to 65535"):
        FirewallPolicy.model_validate(data)


def test_rejects_duplicate_rule_names() -> None:
    data = valid_policy_data()
    rules = data["rules"]
    assert isinstance(rules, list)
    rules[1]["name"] = "allow-docs-ssh"

    with pytest.raises(ValidationError, match="duplicate rule name"):
        FirewallPolicy.model_validate(data)


def test_rejects_duplicate_rule_content() -> None:
    data = valid_policy_data()
    first_rule = {
        "name": "allow-docs-ssh-copy",
        "direction": "input",
        "action": "accept",
        "protocol": "tcp",
        "source": "192.0.2.0/24",
        "destination_port": 22,
        "connection_state": ["established", "related", "new"],
    }
    data["rules"] = [data["rules"][0], first_rule]

    with pytest.raises(ValidationError, match="duplicate rule content"):
        FirewallPolicy.model_validate(data)


def test_rejects_ports_for_icmp_rules() -> None:
    data = valid_policy_data()
    rules = data["rules"]
    assert isinstance(rules, list)
    rules[0]["protocol"] = "icmp"

    with pytest.raises(ValidationError, match="ports are only supported"):
        FirewallPolicy.model_validate(data)


def test_rejects_ipv6_until_supported() -> None:
    data = valid_policy_data()
    rules = data["rules"]
    assert isinstance(rules, list)
    rules[0]["source"] = "2001:db8::/32"

    with pytest.raises(ValidationError, match="IPv4"):
        FirewallPolicy.model_validate(data)
