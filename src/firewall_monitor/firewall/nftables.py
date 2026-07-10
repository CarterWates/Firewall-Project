from __future__ import annotations

from firewall_monitor.core.policy import FirewallPolicy, FirewallRule


def render_nftables_ruleset(policy: FirewallPolicy) -> str:
    """Render a validated policy as nftables ruleset text without applying it."""

    lines = [
        "table inet firewall_monitor {",
        _render_chain_header("input", policy.default_policy.input),
        *_render_rules_for_direction(policy, "input"),
        "  }",
        _render_chain_header("forward", policy.default_policy.forward),
        *_render_rules_for_direction(policy, "forward"),
        "  }",
        _render_chain_header("output", policy.default_policy.output),
        *_render_rules_for_direction(policy, "output"),
        "  }",
        "}",
    ]
    return "\n".join(lines) + "\n"


def _render_chain_header(direction: str, default_policy: str) -> str:
    return (
        f"  chain {direction} {{\n"
        f"    type filter hook {direction} priority 0; policy {default_policy};"
    )


def _render_rules_for_direction(policy: FirewallPolicy, direction: str) -> list[str]:
    return [
        f"    {_render_rule(rule)}"
        for rule in policy.rules
        if rule.direction == direction
    ]


def _render_rule(rule: FirewallRule) -> str:
    expressions: list[str] = []

    if rule.protocol:
        protocol_match = (
            "ip protocol icmp" if rule.protocol == "icmp" else rule.protocol
        )
        expressions.append(protocol_match)
    if rule.source:
        expressions.append(f"ip saddr {rule.source}")
    if rule.destination:
        expressions.append(f"ip daddr {rule.destination}")
    if rule.source_port is not None and rule.protocol in {"tcp", "udp"}:
        expressions.append(f"{rule.protocol} sport {_render_port(rule.source_port)}")
    if rule.destination_port is not None and rule.protocol in {"tcp", "udp"}:
        rendered_port = _render_port(rule.destination_port)
        expressions.append(f"{rule.protocol} dport {rendered_port}")
    if rule.connection_state:
        expressions.append(f"ct state {','.join(rule.connection_state)}")
    if rule.log:
        expressions.append(f'log prefix "firewall-monitor {rule.name}: "')

    expressions.append(rule.action)
    expressions.append(f'comment "{rule.name}"')
    return " ".join(expressions)


def _render_port(port: int | str) -> str:
    if isinstance(port, int):
        return str(port)
    if "-" in port:
        start, end = port.split("-", maxsplit=1)
        return f"{start}-{end}"
    return port
