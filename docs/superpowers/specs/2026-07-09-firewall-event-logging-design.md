# Firewall Event Logging Design

## Goal

Add structured firewall event logging backed by SQLite so the project can retain and inspect blocked traffic events. This is the first monitoring milestone.

## Scope

Phase three parses nftables/kernel-style log lines emitted with the `firewall-monitor <rule>:` prefix, stores normalized events in SQLite, and exposes CLI commands to ingest and list events. It does not tail live logs, run as a daemon, or detect suspicious activity yet.

## Architecture

- `monitoring.events` parses raw log lines into a small `FirewallEvent` dataclass.
- `database.models` defines the SQLAlchemy ORM table.
- `database.session` creates SQLite engines and initializes schema.
- `database.events` stores and queries firewall events.
- `cli.main` adds an `events` command group with `ingest` and `list`.

The parser is intentionally conservative. Lines that do not contain the expected project prefix or core network fields are ignored by returning `None`.

## Data Model

Stored event fields include timestamp, action, rule name, source IP, destination IP, protocol, optional destination port, interface names, and raw message. The timestamp is the ingest time for this milestone because kernel logs often arrive without a complete timestamp in copied samples.

## Security And Privacy

Examples and tests use documentation-only address ranges. Runtime databases are ignored by git. CLI output should not include secrets and should only show event data explicitly ingested by the operator.

## Testing

Unit tests cover parser success and ignore cases, SQLite persistence with ordering and limits, and CLI ingest/list behavior using temporary database files.
