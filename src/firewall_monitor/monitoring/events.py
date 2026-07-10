from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass(frozen=True)
class FirewallEvent:
    """Structured firewall event parsed from a log line."""

    occurred_at: datetime
    action: str
    rule_name: str
    source_ip: str
    destination_ip: str
    protocol: str
    destination_port: int | None
    input_interface: str | None
    output_interface: str | None
    raw_message: str


_PREFIX_RE = re.compile(r"firewall-monitor (?P<rule>[A-Za-z0-9_.-]+):")
_FIELD_RE = re.compile(r"(?P<key>[A-Z]+)=(?P<value>\S*)")


def parse_firewall_log_line(line: str) -> FirewallEvent | None:
    """Parse one firewall-monitor log line into a structured event."""

    prefix_match = _PREFIX_RE.search(line)
    if not prefix_match:
        return None

    fields = {
        match.group("key"): match.group("value")
        for match in _FIELD_RE.finditer(line)
        if match.group("value")
    }
    source_ip = fields.get("SRC")
    destination_ip = fields.get("DST")
    protocol = fields.get("PROTO")
    if not source_ip or not destination_ip or not protocol:
        return None

    destination_port = _parse_optional_int(fields.get("DPT"))
    return FirewallEvent(
        occurred_at=datetime.now(UTC),
        action="blocked",
        rule_name=prefix_match.group("rule"),
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol=protocol.lower(),
        destination_port=destination_port,
        input_interface=fields.get("IN"),
        output_interface=fields.get("OUT"),
        raw_message=line,
    )


def _parse_optional_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None
