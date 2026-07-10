# Phase One Firewall Policy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a safe first milestone that validates YAML firewall policies and generates nftables ruleset text without changing the host firewall.

**Architecture:** Use a `src/firewall_monitor` package with separate modules for policy models, YAML loading, nftables rendering, and Typer CLI commands. Keep firewall generation pure and side-effect free so the initial phase is safe to test on any machine.

**Tech Stack:** Python 3.12+, Pydantic, PyYAML, Typer, pytest, Ruff, mypy, GitHub Actions.

## Global Constraints

- Do not execute nftables commands in phase one.
- Do not require elevated privileges.
- Do not commit secrets, `.env`, caches, databases, logs, or local machine configuration.
- Use IPv4 only in the initial model and document IPv6 as future work.
- Keep code simple, readable, and small enough for a portfolio reviewer to understand quickly.

---

## File Structure

- `pyproject.toml`: package metadata, dependencies, and tool configuration.
- `.gitignore`: local, generated, and sensitive file exclusions.
- `.env.example`: placeholder environment settings only.
- `.github/workflows/ci.yml`: lint, type check, and test workflow.
- `src/firewall_monitor/core/policy.py`: Pydantic policy models and validators.
- `src/firewall_monitor/core/loader.py`: YAML loading and model construction.
- `src/firewall_monitor/firewall/nftables.py`: nftables ruleset rendering.
- `src/firewall_monitor/cli/main.py`: Typer command handlers.
- `tests/unit/test_policy.py`: policy validation tests.
- `tests/unit/test_loader.py`: YAML loading tests.
- `tests/unit/test_nftables.py`: ruleset generation tests.
- `tests/unit/test_cli.py`: dry-run CLI tests.
- `examples/firewall.yaml`: safe documentation example.
- `README.md`: project overview, current scope, commands.
- `SECURITY.md`: supported versions, reporting, assumptions, limitations.
- `AGENTS.md`: development and safety notes for future contributors.

## Task 1: Project Metadata And Tests First

**Files:**
- Create: `pyproject.toml`
- Create: `tests/unit/test_policy.py`
- Create: `tests/unit/test_loader.py`
- Create: `tests/unit/test_nftables.py`
- Create: `tests/unit/test_cli.py`

**Interfaces:**
- Produces: `FirewallPolicy`, `load_policy_file`, `render_nftables_ruleset`, and `app`.

- [ ] Write tests that describe policy validation, loading, generation, and CLI behavior.
- [ ] Run `python3 -m pytest tests/unit -q` and verify failure because implementation does not exist yet.

## Task 2: Core Policy Model

**Files:**
- Create: `src/firewall_monitor/core/policy.py`
- Create: `src/firewall_monitor/core/loader.py`
- Create: package `__init__.py` files.

**Interfaces:**
- Produces: `FirewallPolicy.model_validate(...)`, `load_policy_file(path: Path) -> FirewallPolicy`.

- [ ] Implement the minimal Pydantic models and validators needed for tests.
- [ ] Run `python3 -m pytest tests/unit/test_policy.py tests/unit/test_loader.py -q`.

## Task 3: nftables Renderer And CLI

**Files:**
- Create: `src/firewall_monitor/firewall/nftables.py`
- Create: `src/firewall_monitor/cli/main.py`

**Interfaces:**
- Consumes: `FirewallPolicy`.
- Produces: `render_nftables_ruleset(policy: FirewallPolicy) -> str` and Typer `app`.

- [ ] Implement deterministic nftables output.
- [ ] Implement `validate`, `generate`, and safe `apply --dry-run`.
- [ ] Run `python3 -m pytest tests/unit -q`.

## Task 4: Documentation, CI, And Security Hygiene

**Files:**
- Create: `.gitignore`
- Create: `.env.example`
- Create: `.github/workflows/ci.yml`
- Create: `examples/firewall.yaml`
- Create: `README.md`
- Create: `SECURITY.md`
- Create: `AGENTS.md`

**Interfaces:**
- Produces: contributor-facing docs and automated quality checks.

- [ ] Document phase-one capabilities and limits.
- [ ] Add GitHub Actions for Ruff, mypy, and pytest.
- [ ] Search for secrets and review ignored files.
- [ ] Run `python3 -m ruff check .`, `python3 -m mypy src`, and `python3 -m pytest`.
