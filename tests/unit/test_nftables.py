from firewall_monitor.core.policy import FirewallPolicy
from firewall_monitor.firewall.nftables import render_nftables_ruleset


def test_renders_deterministic_nftables_ruleset() -> None:
    policy = FirewallPolicy.model_validate(
        {
            "version": 1,
            "default_policy": {
                "input": "drop",
                "output": "accept",
                "forward": "drop",
            },
            "rules": [
                {
                    "name": "allow-docs-ssh",
                    "direction": "input",
                    "action": "accept",
                    "protocol": "tcp",
                    "source": "192.0.2.0/24",
                    "destination_port": "22",
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
    )

    ruleset = render_nftables_ruleset(policy)

    assert "table inet firewall_monitor" in ruleset
    assert "chain input {" in ruleset
    assert "type filter hook input priority 0; policy drop;" in ruleset
    assert 'comment "allow-docs-ssh"' in ruleset
    assert "ip saddr 192.0.2.0/24" in ruleset
    assert "tcp dport 22" in ruleset
    assert "ct state established,related,new" in ruleset
    assert "log prefix \"firewall-monitor block-telnet: \"" in ruleset
    assert ruleset.endswith("\n")
