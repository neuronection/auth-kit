from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass(frozen=True)
class AuditEvent:
    actor: str
    action: str
    resource: str
    outcome: str
    tenant_id: str | None = None
    at: datetime | None = None

    def timestamp(self) -> datetime:
        return self.at if self.at is not None else datetime.now(UTC)


class AuditSink:
    """Protocol-shaped base: record one audit event or raise nothing.

    Products plug their table writer in (`SqlAuditSink` ships with the
    SQLAlchemy stores); the null sink keeps call sites unconditional.
    """

    def record(self, event: AuditEvent) -> None:  # pragma: no cover - protocol
        raise NotImplementedError


class NullAuditSink(AuditSink):
    def record(self, event: AuditEvent) -> None:
        del event
