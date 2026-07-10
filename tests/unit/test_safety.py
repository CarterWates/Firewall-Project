from firewall_monitor.core.policy import FirewallPolicy
from firewall_monitor.firewall.safety import FirewallEnvironment, build_apply_plan


def policy_with_ssh_rule() -> FirewallPolicy:
    return FirewallPolicy.model_validate(
        {
            "version": 1,
            "default_policy": {"input": "drop", "output": "accept", "forward": "drop"},
            "rules": [
                {
                    "name": "allow-docs-ssh",
                    "direction": "input",
                    "action": "accept",
                    "protocol": "tcp",
                    "destination_port": 22,
                }
            ],
        }
    )


def policy_without_ssh_rule() -> FirewallPolicy:
    return FirewallPolicy.model_validate(
        {
            "version": 1,
            "default_policy": {"input": "drop", "output": "accept", "forward": "drop"},
            "rules": [
                {
                    "name": "allow-web",
                    "direction": "input",
                    "action": "accept",
                    "protocol": "tcp",
                    "destination_port": 443,
                }
            ],
        }
    )


def test_apply_plan_blocks_future_real_apply_on_non_linux() -> None:
    environment = FirewallEnvironment(
        platform="Darwin",
        is_linux=False,
        is_root=True,
        nft_path="/usr/sbin/nft",
        in_remote_ssh_session=False,
    )

    plan = build_apply_plan(policy_with_ssh_rule(), environment)

    assert "Real apply requires Linux." in plan.blockers


def test_apply_plan_blocks_future_real_apply_without_root() -> None:
    environment = FirewallEnvironment(
        platform="Linux",
        is_linux=True,
        is_root=False,
        nft_path="/usr/sbin/nft",
        in_remote_ssh_session=False,
    )

    plan = build_apply_plan(policy_with_ssh_rule(), environment)

    assert "Real apply requires root privileges." in plan.blockers


def test_apply_plan_warns_about_remote_ssh_drop_without_ssh_allow() -> None:
    environment = FirewallEnvironment(
        platform="Linux",
        is_linux=True,
        is_root=True,
        nft_path="/usr/sbin/nft",
        in_remote_ssh_session=True,
    )

    plan = build_apply_plan(policy_without_ssh_rule(), environment)

    assert plan.has_ssh_accept_rule is False
    assert any("remote SSH session" in warning for warning in plan.warnings)


def test_apply_plan_recognizes_explicit_ssh_allow_rule() -> None:
    environment = FirewallEnvironment(
        platform="Linux",
        is_linux=True,
        is_root=True,
        nft_path="/usr/sbin/nft",
        in_remote_ssh_session=True,
    )

    plan = build_apply_plan(policy_with_ssh_rule(), environment)

    assert plan.has_ssh_accept_rule is True
    assert not any("remote SSH session" in warning for warning in plan.warnings)
