# FastAPI Dashboard Design

## Goal

Add a lightweight FastAPI backend and dashboard so the project can expose stored firewall events and suspicious-source findings through a local web interface.

## Scope

Phase five adds read-only API routes, a simple HTML dashboard, and a CLI `serve` command. It does not add authentication, production deployment, live log tailing, or websocket updates.

## Architecture

- `api.app` creates the FastAPI application.
- API routes read from the existing SQLite repository.
- Detection routes reuse the suspicious-source detector.
- The dashboard is server-rendered HTML from current API data.
- `cli.main` adds `serve` for local development.

The API accepts a database path at app creation time so tests can use temporary databases and local development can use `data/firewall-monitor.sqlite3`.

## Routes

- `GET /health`: service status.
- `GET /api/events?limit=20`: recent firewall events.
- `GET /api/detections?min_attempts=5&window_minutes=15`: suspicious sources.
- `GET /`: lightweight dashboard page.

## Security Notes

The API is intended for local development in this milestone. It should bind to `127.0.0.1` by default. Authentication and hardened deployment are future work.

## Testing

Tests cover health, recent event JSON, detection JSON, and dashboard HTML using a temporary SQLite database.
