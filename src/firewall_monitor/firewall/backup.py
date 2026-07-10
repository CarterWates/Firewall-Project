from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


@dataclass(frozen=True)
class BackupMetadata:
    """Metadata for a written ruleset backup file."""

    path: Path
    created_at: datetime
    bytes_written: int


def build_backup_path(backup_dir: Path, created_at: datetime | None = None) -> Path:
    """Return a timestamped nftables backup path."""

    resolved_created_at = created_at or datetime.now(UTC)
    timestamp = resolved_created_at.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")
    return backup_dir / f"nftables-{timestamp}.nft"


def write_ruleset_backup(
    ruleset: str,
    backup_dir: Path,
    created_at: datetime | None = None,
) -> BackupMetadata:
    """Write caller-supplied ruleset text to a timestamped backup file."""

    resolved_created_at = created_at or datetime.now(UTC)
    backup_dir.mkdir(parents=True, exist_ok=True)
    backup_path = build_backup_path(backup_dir, resolved_created_at)
    backup_path.write_text(ruleset, encoding="utf-8")
    return BackupMetadata(
        path=backup_path,
        created_at=resolved_created_at,
        bytes_written=len(ruleset.encode("utf-8")),
    )
