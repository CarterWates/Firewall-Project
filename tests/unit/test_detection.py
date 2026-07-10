from datetime import UTC, datetime, timedelta

from firewall_monitor.database.events import FirewallEventRepository
from firewall_monitor.database.session import create_sqlite_engine, init_database
from firewall_monitor.detection.blocking import build_temporary_block_plan
from firewall_monitor.detection.suspicious import find_suspicious_sources
from firewall_monitor.monitoring.events import FirewallEvent


def make_event(source_ip: str, occurred_at: datetime) -> FirewallEvent:
    return FirewallEvent(
        occurred_at=occurred_at,
        action="blocked",
        rule_name="block-telnet",
        source_ip=source_ip,
        destination_ip="192.0.2.20",
        protocol="tcp",
        destination_port=23,
        input_interface="eth0",
        output_interface=None,
        raw_message=f"event from {source_ip}",
    )


def test_finds_sources_over_attempt_threshold() -> None:
    now = datetime(2026, 7, 9, 22, 30, tzinfo=UTC)
    events = [
        make_event("203.0.113.10", now - timedelta(minutes=2)),
        make_event("203.0.113.10", now - timedelta(minutes=1)),
        make_event("203.0.113.11", now - timedelta(minutes=1)),
    ]

    findings = find_suspicious_sources(events, min_attempts=2)

    assert len(findings) == 1
    assert findings[0].source_ip == "203.0.113.10"
    assert findings[0].attempt_count == 2


def test_repository_lists_events_since_cutoff(tmp_path) -> None:
    engine = create_sqlite_engine(tmp_path / "events.sqlite3")
    init_database(engine)
    repository = FirewallEventRepository(engine)
    cutoff = datetime(2026, 7, 9, 22, 0, tzinfo=UTC)
    repository.add(make_event("203.0.113.10", cutoff - timedelta(minutes=1)))
    repository.add(make_event("203.0.113.11", cutoff + timedelta(minutes=1)))

    events = repository.list_since(cutoff)

    assert len(events) == 1
    assert events[0].source_ip == "203.0.113.11"


def test_temporary_block_plan_renders_nft_command() -> None:
    now = datetime(2026, 7, 9, 22, 30, tzinfo=UTC)

    plan = build_temporary_block_plan("203.0.113.10", now, duration_minutes=15)

    assert plan.source_ip == "203.0.113.10"
    assert plan.expires_at == now + timedelta(minutes=15)
    assert "ip saddr 203.0.113.10 drop" in plan.nft_rule
    assert "temporary-block expires=2026-07-09T22:45:00+00:00" in plan.nft_rule
