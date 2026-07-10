# Firewall Safety Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add safety checks, backup helpers, and nftables command abstractions without applying firewall rules.

**Architecture:** Add focused firewall modules for environment safety, backup file handling, and nftables command execution behind injectable callables. Update the CLI to expose `status` and richer `apply --dry-run` output while continuing to refuse real apply.

**Tech Stack:** Python 3.12+, Pydantic, PyYAML, Typer, pytest, Ruff, mypy.

## Global Constraints

- Do not execute nftables commands during tests.
- Do not apply firewall rules in this milestone.
- Do not require elevated privileges for normal development.
- Keep examples on documentation-only IP ranges.
- Keep warnings explicit and operationally useful.

---

## File Structure

- `src/firewall_monitor/firewall/safety.py`: environment inspection and apply planning.
- `src/firewall_monitor/firewall/backup.py`: timestamped backup file helpers.
- `src/firewall_monitor/firewall/nft.py`: injectable nftables command client.
- `src/firewall_monitor/cli/main.py`: status command and dry-run safety plan output.
- `tests/unit/test_safety.py`: environment and apply-plan tests.
- `tests/unit/test_backup.py`: backup path and write tests.
- `tests/unit/test_nft_client.py`: nft client command construction tests.
- `tests/unit/test_cli.py`: CLI status and dry-run plan tests.
- `README.md`: document safety layer and next milestones.
- `SECURITY.md`: document no-apply limitation and backup expectations.

## Task 1: Failing Tests

**Files:**
- Create: `tests/unit/test_safety.py`
- Create: `tests/unit/test_backup.py`
- Create: `tests/unit/test_nft_client.py`
- Modify: `tests/unit/test_cli.py`

**Interfaces:**
- Produces expectations for `inspect_environment`, `build_apply_plan`, `build_backup_path`, `write_ruleset_backup`, and `NftablesClient`.

- [ ] Add unit tests for safety checks, backups, nft client, and CLI output.
- [ ] Run `python3 -m pytest tests/unit -q` and confirm failures for missing implementation.

## Task 2: Safety, Backup, And nft Modules

**Files:**
- Create: `src/firewall_monitor/firewall/safety.py`
- Create: `src/firewall_monitor/firewall/backup.py`
- Create: `src/firewall_monitor/firewall/nft.py`

**Interfaces:**
- Produces `inspect_environment() -> FirewallEnvironment`.
- Produces `build_apply_plan(policy, environment) -> ApplyPlan`.
- Produces `write_ruleset_backup(ruleset, backup_dir, created_at=None) -> BackupMetadata`.
- Produces `NftablesClient`.

- [ ] Implement minimal code to satisfy the new tests.
- [ ] Run the focused new tests.

## Task 3: CLI And Documentation

**Files:**
- Modify: `src/firewall_monitor/cli/main.py`
- Modify: `README.md`
- Modify: `SECURITY.md`

**Interfaces:**
- Consumes safety planning and renders user-facing command output.

- [ ] Add `status`.
- [ ] Add safety plan output to `apply --dry-run`.
- [ ] Keep non-dry-run apply refused.
- [ ] Document phase-two capabilities and limits.

## Task 4: Verification And Push

**Files:**
- All changed files.

- [ ] Run `python3 -m ruff check .`.
- [ ] Run `python3 -m mypy src`.
- [ ] Run `python3 -m pytest`.
- [ ] Search staged changes for secret patterns.
- [ ] Commit with `feat: add firewall safety planning layer`.
- [ ] Push `main` to GitHub.
