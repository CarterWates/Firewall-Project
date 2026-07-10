# Linux Firewall and Network Monitoring Platform

This repository is the start of a Python-based Linux host firewall manager. The current milestone focuses on safe policy validation, nftables ruleset generation, and operational safety planning. It does not modify the host firewall.

## Current Capabilities

- Validates YAML firewall policies with Pydantic.
- Supports IPv4 addresses and CIDR ranges.
- Checks directions, actions, protocols, ports, connection states, duplicate names, duplicate rule content, and unsupported protocol/port combinations.
- Generates deterministic nftables ruleset text.
- Provides a Typer CLI for validation, generation, status checks, and dry-run previews.
- Reports future real-apply blockers such as non-Linux hosts, missing `nft`, and missing root privileges.
- Detects remote SSH sessions and warns about policies that could lock out an operator.
- Includes backup helpers and a testable nftables command abstraction for future integration.
- Parses firewall-monitor log lines into structured events.
- Stores firewall events in SQLite and lists recent activity from the CLI.
- Includes unit tests, Ruff, mypy, and GitHub Actions CI.

## Safety Model

The current code is intentionally read-only for normal use. The CLI never applies rules, never requires root privileges, and refuses `apply` unless `--dry-run` is provided. Dry-run output includes a safety plan so future real application can be added carefully.

The repository now includes an nftables client abstraction and backup file helpers, but tests use fakes and supplied ruleset text. Real firewall application, rollback, audit logging, and timed rollback remain future phases and should be developed in an isolated Linux test environment.

## Quick Start

```bash
python -m pip install -e ".[dev]"
firewall-monitor validate examples/firewall.yaml
firewall-monitor status
firewall-monitor generate examples/firewall.yaml
firewall-monitor apply examples/firewall.yaml --dry-run
```

## Event Logging

The event logging milestone works with log files you provide. It does not tail system logs automatically yet.

```bash
firewall-monitor events ingest examples/firewall-events.txt --db ./data/firewall-monitor.sqlite3
firewall-monitor events list --db ./data/firewall-monitor.sqlite3
```

Expected log lines use the prefix emitted by generated logging rules:

```text
firewall-monitor block-telnet: IN=eth0 OUT= SRC=203.0.113.10 DST=192.0.2.20 PROTO=TCP DPT=23
```

## Example Policy

```yaml
version: 1

default_policy:
  input: drop
  output: accept
  forward: drop

rules:
  - name: allow-docs-ssh
    direction: input
    action: accept
    protocol: tcp
    source: 192.0.2.0/24
    destination_port: 22
    connection_state:
      - established
      - related
      - new
```

The example uses documentation-only address space. Replace it with your own test values in a safe lab environment.

## Development

```bash
python -m pip install -e ".[dev]"
python -m ruff check .
python -m mypy src
python -m pytest
```

## Roadmap

- Add ruleset backup and rollback.
- Add explicit, guarded nftables apply support for Linux.
- Add suspicious connection detection and temporary IP blocking.
- Add a FastAPI backend and lightweight dashboard.
- Add systemd service files for Linux deployment.
- Add IPv6 support after the IPv4 model is stable.

## Supported Environment

The code targets Python 3.12 or newer. The generated rules are intended for nftables on Linux, but this first phase can be developed and tested on non-Linux machines because it only renders ruleset text.
