from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Direction = Literal["input", "output", "forward"]
Action = Literal["accept", "drop", "reject"]
Protocol = Literal["tcp", "udp", "icmp"]
DefaultAction = Literal["accept", "drop"]
ConnectionState = Literal["new", "established", "related", "invalid"]

PortValue = Annotated[int | str, Field(description="A port number or range")]


class DefaultPolicy(BaseModel):
    """Default chain policies for the generated ruleset."""

    model_config = ConfigDict(extra="forbid")

    input: DefaultAction
    output: DefaultAction
    forward: DefaultAction


class FirewallRule(BaseModel):
    """One validated firewall rule from a YAML policy file."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$",
    )
    direction: Direction
    action: Action
    protocol: Protocol | None = None
    source: str | None = None
    destination: str | None = None
    source_port: PortValue | None = None
    destination_port: PortValue | None = None
    connection_state: list[ConnectionState] = Field(default_factory=list)
    log: bool = False

    @field_validator("source", "destination")
    @classmethod
    def validate_ipv4_network_or_address(cls, value: str | None) -> str | None:
        if value is None:
            return value
        try:
            if "/" in value:
                network = ip_network(value, strict=False)
                if not isinstance(network, IPv4Network):
                    msg = "only IPv4 addresses and CIDR ranges are supported"
                    raise ValueError(msg)
                return str(network)

            address = ip_address(value)
            if not isinstance(address, IPv4Address):
                msg = "only IPv4 addresses and CIDR ranges are supported"
                raise ValueError(msg)
            return str(address)
        except ValueError as exc:
            msg = "only IPv4 addresses and CIDR ranges are supported"
            raise ValueError(msg) from exc

    @field_validator("source_port", "destination_port")
    @classmethod
    def validate_port(cls, value: PortValue | None) -> PortValue | None:
        if value is None:
            return value
        if isinstance(value, int):
            if 1 <= value <= 65535:
                return value
            msg = "Input should be less than or equal to 65535"
            raise ValueError(msg)

        if "-" not in value:
            try:
                parsed = int(value)
            except ValueError as exc:
                msg = "port must be a number or range"
                raise ValueError(msg) from exc
            if 1 <= parsed <= 65535:
                return parsed
            msg = "Input should be less than or equal to 65535"
            raise ValueError(msg)

        start_text, end_text = value.split("-", maxsplit=1)
        try:
            start = int(start_text)
            end = int(end_text)
        except ValueError as exc:
            msg = "port range must use numeric bounds"
            raise ValueError(msg) from exc
        if not 1 <= start <= end <= 65535:
            msg = "port range must stay within 1-65535"
            raise ValueError(msg)
        return f"{start}-{end}"

    @model_validator(mode="after")
    def validate_protocol_port_combination(self) -> FirewallRule:
        has_port = self.source_port is not None or self.destination_port is not None
        if has_port and self.protocol not in {"tcp", "udp"}:
            msg = "ports are only supported for tcp and udp rules"
            raise ValueError(msg)
        return self

    def semantic_key(self) -> tuple[object, ...]:
        """Return rule content fields used to detect duplicates."""

        return (
            self.direction,
            self.action,
            self.protocol,
            self.source,
            self.destination,
            self.source_port,
            self.destination_port,
            tuple(self.connection_state),
            self.log,
        )


class FirewallPolicy(BaseModel):
    """Top-level firewall policy schema."""

    model_config = ConfigDict(extra="forbid")

    version: Literal[1]
    default_policy: DefaultPolicy
    rules: list[FirewallRule] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_unique_rules(self) -> FirewallPolicy:
        seen_names: set[str] = set()
        seen_content: set[tuple[object, ...]] = set()

        for rule in self.rules:
            if rule.name in seen_names:
                msg = f"duplicate rule name: {rule.name}"
                raise ValueError(msg)
            seen_names.add(rule.name)

            key = rule.semantic_key()
            if key in seen_content:
                msg = f"duplicate rule content: {rule.name}"
                raise ValueError(msg)
            seen_content.add(key)

        return self
