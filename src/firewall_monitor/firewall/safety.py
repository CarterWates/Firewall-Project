from __future__ import annotations

import os
import platform as platform_module
import shutil
from collections.abc import Mapping
from dataclasses import dataclass, field

from firewall_monitor.core.policy import FirewallPolicy, FirewallRule


@dataclass(frozen=True)
class FirewallEnvironment:
    """Runtime facts that matter before applying firewall rules."""

    platform: str
    is_linux: bool
    is_root: bool
    nft_path: str | None
    in_remote_ssh_session: bool


@dataclass(frozen=True)
class ApplyPlan:
    """Operational safety result for a validated policy."""

    blockers: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    has_ssh_accept_rule: bool = False

    @property
    def can_apply(self) -> bool:
        return not self.blockers


def inspect_environment(
    *,
    environ: Mapping[str, str] | None = None,
    platform_name: str | None = None,
    effective_uid: int | None = None,
    nft_path: str | None = None,
) -> FirewallEnvironment:
    """Inspect host facts without changing firewall state."""

    resolved_environ = os.environ if environ is None else environ
    resolved_platform = platform_name or platform_module.system()
    if effective_uid is None:
        geteuid = getattr(os, "geteuid", None)
        effective_uid = geteuid() if geteuid else -1

    resolved_nft_path = nft_path if nft_path is not None else shutil.which("nft")

    return FirewallEnvironment(
        platform=resolved_platform,
        is_linux=resolved_platform == "Linux",
        is_root=effective_uid == 0,
        nft_path=resolved_nft_path,
        in_remote_ssh_session=_detect_remote_ssh(resolved_environ),
    )


def build_apply_plan(
    policy: FirewallPolicy,
    environment: FirewallEnvironment,
) -> ApplyPlan:
    """Build blockers and warnings for a future real firewall apply."""

    blockers: list[str] = []
    warnings: list[str] = []
    has_ssh_accept_rule = any(_is_ssh_accept_rule(rule) for rule in policy.rules)

    if not environment.is_linux:
        blockers.append("Real apply requires Linux.")
    if environment.nft_path is None:
        blockers.append("Real apply requires the nftables binary.")
    if not environment.is_root:
        blockers.append("Real apply requires root privileges.")

    if (
        environment.in_remote_ssh_session
        and policy.default_policy.input == "drop"
        and not has_ssh_accept_rule
    ):
        warnings.append(
            "Detected a remote SSH session with input default drop and no explicit "
            "SSH accept rule."
        )

    return ApplyPlan(
        blockers=blockers,
        warnings=warnings,
        has_ssh_accept_rule=has_ssh_accept_rule,
    )


def _detect_remote_ssh(environ: Mapping[str, str]) -> bool:
    return any(
        environ.get(variable)
        for variable in ("SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY")
    )


def _is_ssh_accept_rule(rule: FirewallRule) -> bool:
    return (
        rule.direction == "input"
        and rule.action == "accept"
        and rule.protocol == "tcp"
        and rule.destination_port == 22
    )
