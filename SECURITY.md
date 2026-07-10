# Security Policy

## Supported Versions

This project is in early development. Security fixes apply to the default branch until tagged releases exist.

## Reporting Vulnerabilities

Do not open a public issue for sensitive vulnerabilities. Report concerns privately through the repository owner's preferred GitHub contact path.

## Security Assumptions

- The current CLI does not apply firewall rules or execute privileged commands.
- Safety planning reports Linux, root, nftables, and remote SSH state before any future apply support is added.
- Backup helpers write caller-supplied ruleset text; they do not collect rules from the host by themselves.
- Event ingestion reads only log files explicitly passed to the CLI.
- Suspicious activity detection prints temporary block recommendations only; it does not execute them.
- The API/dashboard is intended for local development and binds to `127.0.0.1` by default through the CLI.
- Generated nftables output must be reviewed before use.
- Real firewall changes should be tested only in an isolated Linux virtual machine or disposable environment.
- Secrets and machine-specific configuration belong in environment variables or ignored local files.

## Known Limitations

- IPv4 only.
- No real nftables apply support yet.
- No rollback, audit log, monitoring daemon, authentication, or production deployment hardening yet.
- Backup file helpers exist, but there is no automated ruleset collection or rollback yet.
- SQLite event storage exists, but live log tailing is not implemented yet.
- The current tests verify generation and safety-planning behavior, not kernel-level firewall behavior.

## Safe Testing Expectations

Do not test destructive firewall changes on a development workstation. Future integration tests that touch nftables should run in an isolated environment with explicit user approval.
