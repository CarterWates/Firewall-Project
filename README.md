# Linux Firewall and Network Monitoring Platform

This repository is the start of a Python-based Linux host firewall manager. The first milestone focuses on safe policy validation and nftables ruleset generation from YAML. It does not modify the host firewall.

## Current Capabilities

- Validates YAML firewall policies with Pydantic.
- Supports IPv4 addresses and CIDR ranges.
- Checks directions, actions, protocols, ports, connection states, duplicate names, duplicate rule content, and unsupported protocol/port combinations.
- Generates deterministic nftables ruleset text.
- Provides a Typer CLI for validation, generation, and dry-run previews.
- Includes unit tests, Ruff, mypy, and GitHub Actions CI.

## Safety Model

Phase one is intentionally read-only. The CLI never executes `nft`, never requires root privileges, and refuses `apply` unless `--dry-run` is provided. Real firewall application, backups, rollback, audit logging, and timed rollback are future phases and should be developed in an isolated Linux test environment.

## Quick Start

```bash
python -m pip install -e ".[dev]"
firewall-monitor validate examples/firewall.yaml
firewall-monitor generate examples/firewall.yaml
firewall-monitor apply examples/firewall.yaml --dry-run
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
- Add structured firewall event logging.
- Add suspicious connection detection and temporary IP blocking.
- Add SQLite persistence.
- Add a FastAPI backend and lightweight dashboard.
- Add systemd service files for Linux deployment.
- Add IPv6 support after the IPv4 model is stable.

## Supported Environment

The code targets Python 3.12 or newer. The generated rules are intended for nftables on Linux, but this first phase can be developed and tested on non-Linux machines because it only renders ruleset text.
