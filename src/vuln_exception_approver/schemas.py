"""Schemas and Pydantic models for vulnerability exception approval and risk governance."""

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _utc_now() -> datetime:
    return datetime.now(UTC)


class ApprovalStatus(StrEnum):
    """Governance status of a vulnerability exception."""

    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    PENDING_REVIEW = "PENDING_REVIEW"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


class ApprovalRequest(BaseModel):
    """Incoming request payload for vulnerability exception approval."""

    model_config = ConfigDict(extra="ignore")

    cve_id: str = Field(..., description="CVE identifier (format: CVE-YYYY-NNNNN)")
    package_name: str = Field(..., min_length=1, description="Target package name")
    installed_version: str = Field(..., min_length=1, description="Installed package version")
    severity: str = Field(..., description="Vulnerability severity level (CRITICAL, HIGH, MEDIUM, LOW)")
    epss_score: float = Field(..., ge=0.0, le=1.0, description="FIRST.org EPSS exploit probability")
    in_memory: bool = Field(..., description="True if executable mapped in active Linux process memory")
    ticket_path: str = Field(..., description="Path to the Markdown exception ticket")
    memory_visibility: str = Field(
        default="full",
        description="'full' if in_memory covers all host processes, 'partial' if root-owned processes were not checked",
    )
    remediation_attempted: bool = Field(
        default=True,
        description="True if automated patching and safe purging were attempted and failed",
    )
    compensating_control_active: bool = Field(
        default=False,
        description="True if an active runtime compensating control (e.g. Falco eBPF rule) is verified",
    )
    compensating_control_ref: str | None = Field(
        default=None,
        description="Identifier or rule filename of the active compensating control",
    )
    justification: str = Field(..., min_length=1, description="Technical justification for exception")
    requested_by: str = Field(
        default="vuln-exception-requester",
        description="Origin micro-agent or identity requesting the exception",
    )
    requested_at: datetime = Field(
        default_factory=_utc_now,
        description="Timestamp when exception was requested",
    )

    @field_validator("cve_id", mode="before")
    @classmethod
    def validate_cve_format(cls, value: str) -> str:
        """Validate and normalize CVE identifier to uppercase."""
        cleaned = value.strip().upper()
        if not cleaned.startswith("CVE-"):
            raise ValueError(f"Invalid CVE identifier: {value}. Must start with 'CVE-'")
        return cleaned


class ApprovalDecision(BaseModel):
    """Result payload produced by governance decision gate."""

    model_config = ConfigDict(extra="ignore")

    cve_id: str
    package_name: str
    status: ApprovalStatus
    decision_reason: str
    epss_score: float
    in_memory: bool
    approved_at: datetime | None = None
    expires_at: datetime | None = None
    remediation_sla_deadline: datetime | None = None
    remediation_sla_days: int | None = None
    compensating_control_active: bool = False
    compensating_control_ref: str | None = None
    evaluated_by: str = "vuln-exception-approver"
    evaluated_at: datetime = Field(default_factory=_utc_now)
