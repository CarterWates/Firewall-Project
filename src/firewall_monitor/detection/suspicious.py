from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol


class EventLike(Protocol):
    occurred_at: datetime
    source_ip: str


@dataclass(frozen=True)
class SuspiciousSource:
    """A source IP with repeated blocked events."""

    source_ip: str
    attempt_count: int
    first_seen: datetime
    last_seen: datetime


def find_suspicious_sources(
    events: Sequence[EventLike],
    *,
    min_attempts: int,
) -> list[SuspiciousSource]:
    """Group events by source IP and return sources over the threshold."""

    grouped: dict[str, list[EventLike]] = defaultdict(list)
    for event in events:
        grouped[event.source_ip].append(event)

    findings = [
        SuspiciousSource(
            source_ip=source_ip,
            attempt_count=len(source_events),
            first_seen=min(event.occurred_at for event in source_events),
            last_seen=max(event.occurred_at for event in source_events),
        )
        for source_ip, source_events in grouped.items()
        if len(source_events) >= min_attempts
    ]
    return sorted(findings, key=lambda item: (-item.attempt_count, item.source_ip))
