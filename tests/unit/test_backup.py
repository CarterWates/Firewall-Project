from datetime import UTC, datetime

from firewall_monitor.firewall.backup import build_backup_path, write_ruleset_backup


def test_build_backup_path_uses_stable_timestamp(tmp_path) -> None:
    created_at = datetime(2026, 7, 9, 22, 15, 30, tzinfo=UTC)

    path = build_backup_path(tmp_path, created_at)

    assert path.name == "nftables-20260709T221530Z.nft"
    assert path.parent == tmp_path


def test_write_ruleset_backup_writes_supplied_text(tmp_path) -> None:
    created_at = datetime(2026, 7, 9, 22, 15, 30, tzinfo=UTC)

    metadata = write_ruleset_backup("table inet test {}\n", tmp_path, created_at)

    assert metadata.path.exists()
    assert metadata.path.read_text(encoding="utf-8") == "table inet test {}\n"
    assert metadata.bytes_written == len(b"table inet test {}\n")
