# Firewall Safety Layer Design

## Goal

Add the operational safety layer needed before real firewall changes are ever attempted. This milestone should make the project look more like a practical security tool while still avoiding destructive host changes.

## Scope

Phase two adds environment inspection, apply planning, SSH-risk warnings, backup path helpers, and a testable nftables command abstraction. CLI commands may report status and render dry-run plans, but they must not apply rules to the host firewall.

## Architecture

- `firewall_monitor.firewall.safety` inspects the runtime environment and builds an apply plan with warnings and blockers.
- `firewall_monitor.firewall.backup` creates timestamped backup paths and writes supplied ruleset text to backup files.
- `firewall_monitor.firewall.nft` wraps nftables command execution behind a small injectable runner so tests do not call the real `nft` binary.
- `firewall_monitor.cli.main` adds `status` output and improves `apply --dry-run` by showing safety checks before generated rules.

The safety planner does not decide policy validity; it consumes a validated `FirewallPolicy`. It answers a separate operational question: would this be safe to attempt in a real Linux environment, and what should the operator notice first?

## Safety Rules

- Real apply remains unavailable in this milestone.
- Non-Linux hosts, missing `nft`, and missing root privileges are blockers for future real apply.
- Remote SSH sessions are detected from `SSH_CONNECTION`, `SSH_CLIENT`, or `SSH_TTY`.
- A remote SSH session plus an input default drop policy is a warning unless the policy has an explicit SSH accept rule.
- Backup helpers write only caller-supplied text and do not call nftables.
- The nftables client exists for future integration but is tested with fake runners.

## Testing

Unit tests cover Linux/non-Linux environment inspection, SSH detection, apply-plan blockers and warnings, safe backup naming, backup writes, nft client command construction, and CLI status/dry-run output.
