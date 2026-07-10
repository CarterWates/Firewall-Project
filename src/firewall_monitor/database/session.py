from __future__ import annotations

from pathlib import Path

from sqlalchemy import Engine, create_engine

from firewall_monitor.database.models import Base


def create_sqlite_engine(path: Path) -> Engine:
    """Create a SQLite engine for the monitoring database."""

    path.parent.mkdir(parents=True, exist_ok=True)
    return create_engine(f"sqlite:///{path}", future=True)


def init_database(engine: Engine) -> None:
    """Create database tables if they do not already exist."""

    Base.metadata.create_all(engine)
