# FastAPI Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose stored firewall events and suspicious-source findings through a local FastAPI API and dashboard.

**Architecture:** Add `api.app` with app factory routes backed by SQLite repositories and detection helpers. Add a CLI `serve` command that starts uvicorn on localhost by default.

**Tech Stack:** Python 3.12+, FastAPI, Uvicorn, SQLAlchemy, Typer, pytest, Ruff, mypy.

## Global Constraints

- API is local-development oriented.
- Bind `serve` to `127.0.0.1` by default.
- Keep routes read-only.
- Do not claim production readiness.

---

## File Structure

- `src/firewall_monitor/api/__init__.py`: API package.
- `src/firewall_monitor/api/app.py`: FastAPI app factory and routes.
- `src/firewall_monitor/cli/main.py`: `serve` command.
- `tests/unit/test_api.py`: FastAPI route tests.
- `pyproject.toml`: add FastAPI, Uvicorn, HTTPX test dependency.
- `README.md`: document API/dashboard usage.

## Task 1: Failing Tests

- [ ] Add FastAPI route tests.
- [ ] Run `python3 -m pytest tests/unit/test_api.py -q` and confirm missing implementation failure.

## Task 2: API App

- [ ] Implement app factory, JSON routes, and dashboard HTML.
- [ ] Run API tests.

## Task 3: CLI And Docs

- [ ] Add `serve` command.
- [ ] Update README and security notes.

## Task 4: Verification And Push

- [ ] Run `python3 -m ruff check .`.
- [ ] Run `python3 -m mypy src`.
- [ ] Run `python3 -m pytest`.
- [ ] Search staged changes for secret patterns.
- [ ] Commit with `feat: add FastAPI monitoring dashboard`.
- [ ] Push `main` to GitHub.
