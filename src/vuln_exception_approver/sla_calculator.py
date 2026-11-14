"""SLA and expiration calculation module for vulnerability exceptions."""

from datetime import UTC, datetime, timedelta


def calculate_expiration(severity: str, from_date: datetime | None = None) -> tuple[datetime, int]:
    """Calculate expiration date and lifespan in days for an approved exception.

    Rules:
    - CRITICAL and HIGH severity: 30 calendar days.
    - MEDIUM, LOW, and others: 90 calendar days.
    """
    base_date = from_date or datetime.now(UTC)
    normalized = severity.strip().upper()

    days = 30 if normalized in ("CRITICAL", "HIGH") else 90

    expires_at = base_date + timedelta(days=days)
    return expires_at, days


def calculate_remediation_sla(
    severity: str, from_date: datetime | None = None
) -> tuple[datetime, int]:
    """Calculate mandatory remediation SLA deadline for rejected or revoked exceptions.

    Rules:
    - CRITICAL: 7 calendar days.
    - HIGH: 14 calendar days.
    - MEDIUM: 30 calendar days.
    - LOW: 60 calendar days.
    """
    base_date = from_date or datetime.now(UTC)
    normalized = severity.strip().upper()

    if normalized == "CRITICAL":
        days = 7
    elif normalized == "HIGH":
        days = 14
    elif normalized == "MEDIUM":
        days = 30
    else:
        days = 60

    deadline = base_date + timedelta(days=days)
    return deadline, days
