# Phase One Firewall Policy Design

## Goal

Build the first safe milestone for a Linux firewall monitoring portfolio project: a Python package that validates human-readable YAML firewall policies and renders nftables ruleset text without modifying the host firewall.

## Scope

Phase one includes repository setup, policy parsing, validation, nftables text generation, a dry-run CLI, unit tests, documentation, and CI. It does not execute nftables commands, require privileges, alter system firewall state, start a daemon, or expose an API/dashboard yet.

## Architecture

The code uses a small `src/` layout with focused modules:

- `firewall_monitor.core.policy` defines the validated policy model.
- `firewall_monitor.core.loader` reads YAML into that model.
- `firewall_monitor.firewall.nftables` turns a validated policy into nftables ruleset text.
- `firewall_monitor.cli.main` exposes `validate`, `generate`, and `apply --dry-run`.

The generator is deliberately pure: it returns a string and never shells out. That keeps early development safe and makes tests straightforward.

## Validation Rules

The initial model supports IPv4 only. It validates default policies, rule names, directions, actions, protocols, IPv4 addresses and CIDR ranges, ports, port ranges, connection states, duplicate rule names, duplicate rule content, and unsupported protocol/port combinations.

IPv6, real rule application, rollback, event logging, suspicious activity detection, SQLite persistence, FastAPI, and systemd integration are documented as future phases.

## Security And Operational Notes

The program must not apply firewall rules in this phase. The CLI `apply` command requires `--dry-run` and returns an error otherwise. Documentation must avoid private IPs tied to the user's real network and use documentation-only ranges.

Before commit, inspect staged changes for secrets, ensure `.env` is ignored, and confirm generated caches, database files, and local virtual environments are ignored.

## Testing

Unit tests cover representative valid policies, invalid defaults, invalid ports, duplicate rules, unsupported protocol/port combinations, YAML loading failures, and deterministic nftables output.
