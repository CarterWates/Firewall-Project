# Security Policy

## Supported Versions

This project is in early development. Security fixes apply to the default branch until tagged releases exist.

## Reporting Vulnerabilities

Do not open a public issue for sensitive vulnerabilities. Report concerns privately through the repository owner's preferred GitHub contact path.

## Security Assumptions

- Phase one does not apply firewall rules or execute privileged commands.
- Generated nftables output must be reviewed before use.
- Real firewall changes should be tested only in an isolated Linux virtual machine or disposable environment.
- Secrets and machine-specific configuration belong in environment variables or ignored local files.

## Known Limitations

- IPv4 only.
- No real nftables apply support yet.
- No backup, rollback, audit log, monitoring daemon, dashboard, or detection engine yet.
- The current tests verify generation behavior, not kernel-level firewall behavior.

## Safe Testing Expectations

Do not test destructive firewall changes on a development workstation. Future integration tests that touch nftables should run in an isolated environment with explicit user approval.
