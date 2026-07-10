from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass(frozen=True)
class TemporaryBlockPlan:
    """Dry-run recommendation for a temporary source IP block."""

    source_ip: str
    expires_at: datetime
    nft_rule: str


def build_temporary_block_plan(
    source_ip: str,
    created_at: datetime,
    *,
    duration_minutes: int,
) -> TemporaryBlockPlan:
    """Render a temporary nftables block rule without executing it."""

    expires_at = created_at + timedelta(minutes=duration_minutes)
    nft_rule = (
        "add rule inet firewall_monitor input "
        f'ip saddr {source_ip} drop comment "temporary-block '
        f'expires={expires_at.isoformat()}"'
    )
    return TemporaryBlockPlan(
        source_ip=source_ip,
        expires_at=expires_at,
        nft_rule=nft_rule,
    )
