from __future__ import annotations

from datetime import UTC, datetime, timedelta
from html import escape
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse

from firewall_monitor.database.events import FirewallEventRepository
from firewall_monitor.database.models import FirewallEventRecord
from firewall_monitor.database.session import create_sqlite_engine, init_database
from firewall_monitor.detection.suspicious import find_suspicious_sources


def create_app(db_path: Path) -> FastAPI:
    """Create a read-only monitoring API backed by a SQLite database."""

    engine = create_sqlite_engine(db_path)
    init_database(engine)
    repository = FirewallEventRepository(engine)
    app = FastAPI(title="Firewall Monitor API")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/events")
    def recent_events(limit: int = Query(20, ge=1, le=200)) -> dict[str, Any]:
        events = repository.list_recent(limit=limit)
        return {
            "count": len(events),
            "events": [_event_to_api(event) for event in events],
        }

    @app.get("/api/detections")
    def detections(
        min_attempts: int = Query(5, ge=2, le=1000),
        window_minutes: int = Query(15, ge=1, le=1440),
    ) -> dict[str, Any]:
        since = datetime.now(UTC) - timedelta(minutes=window_minutes)
        findings = find_suspicious_sources(
            repository.list_since(since),
            min_attempts=min_attempts,
        )
        return {
            "count": len(findings),
            "detections": [
                {
                    "source_ip": finding.source_ip,
                    "attempt_count": finding.attempt_count,
                    "first_seen": finding.first_seen.isoformat(),
                    "last_seen": finding.last_seen.isoformat(),
                }
                for finding in findings
            ],
        }

    @app.get("/", response_class=HTMLResponse)
    def dashboard() -> str:
        events = repository.list_recent(limit=20)
        findings = find_suspicious_sources(
            repository.list_since(datetime.now(UTC) - timedelta(minutes=15)),
            min_attempts=5,
        )
        return _render_dashboard(events, findings)

    return app


def _event_to_api(event: FirewallEventRecord) -> dict[str, Any]:
    return {
        "occurred_at": event.occurred_at.isoformat(),
        "action": event.action,
        "rule_name": event.rule_name,
        "source_ip": event.source_ip,
        "destination_ip": event.destination_ip,
        "protocol": event.protocol,
        "destination_port": event.destination_port,
        "input_interface": event.input_interface,
        "output_interface": event.output_interface,
    }


def _render_dashboard(
    events: list[FirewallEventRecord],
    detections: list[Any],
) -> str:
    event_rows = "\n".join(
        "<tr>"
        f"<td>{escape(event.occurred_at.isoformat())}</td>"
        f"<td>{escape(event.source_ip)}</td>"
        f"<td>{escape(event.destination_ip)}</td>"
        f"<td>{escape(event.protocol)}</td>"
        f"<td>{event.destination_port or ''}</td>"
        f"<td>{escape(event.rule_name)}</td>"
        "</tr>"
        for event in events
    )
    detection_rows = "\n".join(
        "<tr>"
        f"<td>{escape(finding.source_ip)}</td>"
        f"<td>{finding.attempt_count}</td>"
        f"<td>{escape(finding.first_seen.isoformat())}</td>"
        f"<td>{escape(finding.last_seen.isoformat())}</td>"
        "</tr>"
        for finding in detections
    )
    if not event_rows:
        event_rows = '<tr><td colspan="6">No events found.</td></tr>'
    if not detection_rows:
        detection_rows = '<tr><td colspan="4">No suspicious sources found.</td></tr>'

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Firewall Monitor</title>
  <style>
    body {{
      color: #17202a;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      margin: 0;
      background: #f5f7fb;
    }}
    header {{
      background: #17202a;
      color: white;
      padding: 24px 32px;
    }}
    main {{
      max-width: 1180px;
      margin: 0 auto;
      padding: 28px 20px 48px;
    }}
    section {{
      margin-bottom: 32px;
    }}
    h1, h2 {{
      margin: 0 0 12px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: white;
      border: 1px solid #d9e2ec;
    }}
    th, td {{
      border-bottom: 1px solid #e6edf3;
      padding: 10px 12px;
      text-align: left;
      font-size: 14px;
    }}
    th {{
      background: #eef3f8;
      font-weight: 700;
    }}
  </style>
</head>
<body>
  <header>
    <h1>Firewall Monitor</h1>
    <p>Recent blocked traffic and suspicious source summaries.</p>
  </header>
  <main>
    <section>
      <h2>Suspicious Sources</h2>
      <table>
        <thead>
          <tr>
            <th>Source IP</th><th>Attempts</th>
            <th>First Seen</th><th>Last Seen</th>
          </tr>
        </thead>
        <tbody>{detection_rows}</tbody>
      </table>
    </section>
    <section>
      <h2>Recent Events</h2>
      <table>
        <thead>
          <tr>
            <th>Time</th><th>Source</th><th>Destination</th>
            <th>Protocol</th><th>Port</th><th>Rule</th>
          </tr>
        </thead>
        <tbody>{event_rows}</tbody>
      </table>
    </section>
  </main>
</body>
</html>"""
