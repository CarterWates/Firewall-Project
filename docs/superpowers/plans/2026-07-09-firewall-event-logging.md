# Firewall Event Logging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Parse firewall log lines, store structured events in SQLite, and inspect them from the CLI.

**Architecture:** Add a monitoring parser, SQLAlchemy database setup, event repository, and Typer `events` command group. Keep live log tailing and detection for later milestones.

**Tech Stack:** Python 3.12+, SQLAlchemy, Typer, pytest, Ruff, mypy.

## Global Constraints

- Do not ingest real system logs automatically.
- Do not commit SQLite databases or logs.
- Use documentation-only IP addresses in tests and examples.
- Keep parsing conservative and predictable.

---

## File Structure

- `src/firewall_monitor/monitoring/events.py`: event dataclass and log parser.
- `src/firewall_monitor/database/models.py`: SQLAlchemy event ORM model.
- `src/firewall_monitor/database/session.py`: engine and schema helpers.
- `src/firewall_monitor/database/events.py`: repository methods.
- `src/firewall_monitor/cli/main.py`: `events ingest` and `events list`.
- `tests/unit/test_event_parser.py`: parser tests.
- `tests/unit/test_event_repository.py`: SQLite repository tests.
- `tests/unit/test_cli_events.py`: CLI ingest/list tests.
- `pyproject.toml`: add SQLAlchemy.
- `README.md`: document event logging milestone.

## Task 1: Failing Tests

**Files:**
- Create: `tests/unit/test_event_parser.py`
- Create: `tests/unit/test_event_repository.py`
- Create: `tests/unit/test_cli_events.py`

- [ ] Add parser, repository, and CLI tests.
- [ ] Run `python3 -m pytest tests/unit -q` and confirm missing implementation failures.

## Task 2: Parser And Database

**Files:**
- Create: `src/firewall_monitor/monitoring/events.py`
- Create: `src/firewall_monitor/database/__init__.py`
- Create: `src/firewall_monitor/database/models.py`
- Create: `src/firewall_monitor/database/session.py`
- Create: `src/firewall_monitor/database/events.py`

- [ ] Implement event parsing.
- [ ] Implement SQLite schema and repository.
- [ ] Run focused parser and repository tests.

## Task 3: CLI And Docs

**Files:**
- Modify: `src/firewall_monitor/cli/main.py`
- Modify: `README.md`
- Modify: `pyproject.toml`

- [ ] Add SQLAlchemy dependency.
- [ ] Add `events ingest` and `events list`.
- [ ] Document usage and limitations.

## Task 4: Verification And Push

- [ ] Run `python3 -m ruff check .`.
- [ ] Run `python3 -m mypy src`.
- [ ] Run `python3 -m pytest`.
- [ ] Search staged changes for secret patterns.
- [ ] Commit with `feat: add structured firewall event logging`.
- [ ] Push `main` to GitHub.
