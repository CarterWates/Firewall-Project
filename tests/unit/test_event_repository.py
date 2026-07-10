from datetime import UTC, datetime

from firewall_monitor.database.events import FirewallEventRepository
from firewall_monitor.database.session import create_sqlite_engine, init_database
from firewall_monitor.monitoring.events import FirewallEvent


def test_repository_stores_and_lists_events(tmp_path) -> None:
    engine = create_sqlite_engine(tmp_path / "events.sqlite3")
    init_database(engine)
    repository = FirewallEventRepository(engine)
    older = FirewallEvent(
        occurred_at=datetime(2026, 7, 9, 22, 0, tzinfo=UTC),
        action="blocked",
        rule_name="block-telnet",
        source_ip="203.0.113.10",
        destination_ip="192.0.2.20",
        protocol="tcp",
        destination_port=23,
        input_interface="eth0",
        output_interface=None,
        raw_message="older",
    )
    newer = FirewallEvent(
        occurred_at=datetime(2026, 7, 9, 22, 5, tzinfo=UTC),
        action="blocked",
        rule_name="block-web",
        source_ip="203.0.113.11",
        destination_ip="192.0.2.20",
        protocol="tcp",
        destination_port=443,
        input_interface="eth0",
        output_interface=None,
        raw_message="newer",
    )

    repository.add(older)
    repository.add(newer)

    events = repository.list_recent(limit=1)

    assert len(events) == 1
    assert events[0].rule_name == "block-web"
    assert repository.count() == 2
