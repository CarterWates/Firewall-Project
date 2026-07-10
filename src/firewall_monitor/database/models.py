from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Base class for ORM models."""


class FirewallEventRecord(Base):
    """Stored firewall event."""

    __tablename__ = "firewall_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    action: Mapped[str] = mapped_column(String(32))
    rule_name: Mapped[str] = mapped_column(String(128), index=True)
    source_ip: Mapped[str] = mapped_column(String(64), index=True)
    destination_ip: Mapped[str] = mapped_column(String(64))
    protocol: Mapped[str] = mapped_column(String(16))
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    input_interface: Mapped[str | None] = mapped_column(String(64), nullable=True)
    output_interface: Mapped[str | None] = mapped_column(String(64), nullable=True)
    raw_message: Mapped[str] = mapped_column(Text)
