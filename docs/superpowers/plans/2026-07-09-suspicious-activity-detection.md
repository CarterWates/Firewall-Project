# Suspicious Activity Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Identify repeated suspicious sources from stored firewall events and print dry-run temporary block recommendations.

**Architecture:** Add detection modules for grouping event records and rendering temporary block plans. Extend the repository with time-window queries and expose the workflow through `firewall-monitor detect scan`.

**Tech Stack:** Python 3.12+, SQLAlchemy, Typer, pytest, Ruff, mypy.

## Global Constraints

- Do not execute nftables commands.
- Do not persist block decisions yet.
- Use stored event data as the detection input.
- Keep output clear that recommendations are dry-run only.

---

## File Structure

- `src/firewall_monitor/detection/suspicious.py`: repeated-source detection.
- `src/firewall_monitor/detection/blocking.py`: temporary block recommendation rendering.
- `src/firewall_monitor/database/events.py`: `list_since`.
- `src/firewall_monitor/cli/main.py`: `detect scan`.
- `tests/unit/test_detection.py`: detection and block plan tests.
- `tests/unit/test_cli_detect.py`: CLI scan tests.
- `README.md`: detection usage.

## Task 1: Failing Tests

- [ ] Add tests for detection, block rendering, repository `list_since`, and CLI output.
- [ ] Run `python3 -m pytest tests/unit -q` and confirm missing implementation failures.

## Task 2: Detection Modules

- [ ] Implement suspicious-source grouping and threshold filtering.
- [ ] Implement temporary block plan rendering.
- [ ] Run focused detection tests.

## Task 3: Repository And CLI

- [ ] Add repository `list_since`.
- [ ] Add `detect scan` CLI command.
- [ ] Update README.

## Task 4: Verification And Push

- [ ] Run `python3 -m ruff check .`.
- [ ] Run `python3 -m mypy src`.
- [ ] Run `python3 -m pytest`.
- [ ] Search staged changes for secret patterns.
- [ ] Commit with `feat: add suspicious activity detection`.
- [ ] Push `main` to GitHub.
