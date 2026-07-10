from __future__ import annotations

from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session

from firewall_monitor.database.models import FirewallEventRecord
from firewall_monitor.monitoring.events import FirewallEvent


class FirewallEventRepository:
    """Persistence operations for firewall events."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def add(self, event: FirewallEvent) -> FirewallEventRecord:
        record = FirewallEventRecord(
            occurred_at=event.occurred_at,
            action=event.action,
            rule_name=event.rule_name,
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            protocol=event.protocol,
            destination_port=event.destination_port,
            input_interface=event.input_interface,
            output_interface=event.output_interface,
            raw_message=event.raw_message,
        )
        with Session(self._engine) as session:
            session.add(record)
            session.commit()
            session.refresh(record)
            return record

    def list_recent(self, limit: int = 50) -> list[FirewallEventRecord]:
        statement = (
            select(FirewallEventRecord)
            .order_by(FirewallEventRecord.occurred_at.desc())
            .limit(limit)
        )
        with Session(self._engine) as session:
            return list(session.scalars(statement))

    def count(self) -> int:
        statement = select(func.count()).select_from(FirewallEventRecord)
        with Session(self._engine) as session:
            return session.execute(statement).scalar_one()
