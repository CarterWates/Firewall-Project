from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient

from firewall_monitor.api.app import create_app
from firewall_monitor.database.events import FirewallEventRepository
from firewall_monitor.database.session import create_sqlite_engine, init_database
from firewall_monitor.monitoring.events import FirewallEvent


def seed_events(db_path: Path) -> None:
    engine = create_sqlite_engine(db_path)
    init_database(engine)
    repository = FirewallEventRepository(engine)
    for _ in range(3):
        repository.add(
            FirewallEvent(
                occurred_at=datetime.now(UTC),
                action="blocked",
                rule_name="block-telnet",
                source_ip="203.0.113.10",
                destination_ip="192.0.2.20",
                protocol="tcp",
                destination_port=23,
                input_interface="eth0",
                output_interface=None,
                raw_message="test",
            )
        )


def test_health_route(tmp_path: Path) -> None:
    client = TestClient(create_app(tmp_path / "events.sqlite3"))

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_events_route_returns_recent_events(tmp_path: Path) -> None:
    db_path = tmp_path / "events.sqlite3"
    seed_events(db_path)
    client = TestClient(create_app(db_path))

    response = client.get("/api/events")

    assert response.status_code == 200
    payload = response.json()
    assert payload["count"] == 3
    assert payload["events"][0]["source_ip"] == "203.0.113.10"


def test_detections_route_returns_suspicious_sources(tmp_path: Path) -> None:
    db_path = tmp_path / "events.sqlite3"
    seed_events(db_path)
    client = TestClient(create_app(db_path))

    response = client.get("/api/detections?min_attempts=3&window_minutes=60")

    assert response.status_code == 200
    payload = response.json()
    assert payload["count"] == 1
    assert payload["detections"][0]["source_ip"] == "203.0.113.10"


def test_dashboard_route_returns_html(tmp_path: Path) -> None:
    db_path = tmp_path / "events.sqlite3"
    seed_events(db_path)
    client = TestClient(create_app(db_path))

    response = client.get("/")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Firewall Monitor" in response.text
    assert "203.0.113.10" in response.text
