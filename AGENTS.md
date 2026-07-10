# Agent Notes

This project is a resume-quality cybersecurity and cloud engineering portfolio project. Keep changes small, reviewable, and honest about current limitations.

## Safety Rules

- Do not execute nftables commands unless a later phase explicitly approves it.
- Do not add privileged operations to tests.
- Do not commit secrets, `.env` files, local database files, logs, caches, certificates, or private keys.
- Use documentation-only networks such as `192.0.2.0/24` in examples and tests.
- Prefer clear validation errors over clever abstractions.

## Verification

Before committing, run:

```bash
python -m ruff check .
python -m mypy src
python -m pytest
```
