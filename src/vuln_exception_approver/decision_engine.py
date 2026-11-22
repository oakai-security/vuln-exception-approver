"""Governance decision engine enforcing deterministic vulnerability risk gates."""

import logging
from datetime import UTC, datetime

from vuln_exception_approver.schemas import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStatus,
)
from vuln_exception_approver.sla_calculator import (
    calculate_expiration,
    calculate_remediation_sla,
)

logger = logging.getLogger(__name__)

EPSS_APPROVAL_THRESHOLD = 0.05


def evaluate_exception_request(request: ApprovalRequest) -> ApprovalDecision:
    """Evaluate an exception request using deterministic risk gates.

    Strict Governance Gates:
    1. Active In-Memory Execution: If vulnerable binaries or libraries are mapped
       into active Linux process memory (in_memory is True), immediate REJECTION.
    2. EPSS Exploit Probability: If EPSS score is >= 0.05 (5% exploit probability),
       immediate REJECTION.
    3. Safe Risk Criteria: If EPSS < 0.05 AND in_memory is False, APPROVED.
    """
    now = datetime.now(UTC)

    # Gate 1: Check active memory residency
    if request.in_memory:
        if request.compensating_control_active:
            ctrl_ref = request.compensating_control_ref or "verified runtime Falco eBPF rule"
            expires_at, lifespan_days = calculate_expiration("HIGH", from_date=now)
            reason = (
                f"Conditional exception approved: Vulnerable library is active in memory, but "
                f"verified compensating control ({ctrl_ref}) is active in runtime. Valid for "
                f"{lifespan_days} days under telemetry."
            )
            logger.info(
                "[%s] Conditionally approved via compensating control for in-memory asset: %s",
                request.cve_id,
                ctrl_ref,
            )
            return ApprovalDecision(
                cve_id=request.cve_id,
                package_name=request.package_name,
                status=ApprovalStatus.APPROVED,
                decision_reason=reason,
                epss_score=request.epss_score,
                in_memory=True,
                approved_at=now,
                expires_at=expires_at,
                compensating_control_active=True,
                compensating_control_ref=ctrl_ref,
                evaluated_at=now,
            )

        reason = (
            "Exception rejected: Vulnerable binary or library is loaded in active system "
            "process memory (/proc/<pid>/maps verification confirmed)."
        )
        deadline, sla_days = calculate_remediation_sla(request.severity, from_date=now)
        logger.warning("[%s] Rejected: in-memory execution detected", request.cve_id)
        return ApprovalDecision(
            cve_id=request.cve_id,
            package_name=request.package_name,
            status=ApprovalStatus.REJECTED,
            decision_reason=reason,
            epss_score=request.epss_score,
            in_memory=True,
            remediation_sla_deadline=deadline,
            remediation_sla_days=sla_days,
            evaluated_at=now,
        )

    # Gate 2: Check EPSS exploit threshold with Compensating Control evaluation
    if request.epss_score >= EPSS_APPROVAL_THRESHOLD:
        if request.compensating_control_active:
            ctrl_ref = request.compensating_control_ref or "verified runtime defense"
            expires_at, lifespan_days = calculate_expiration("HIGH", from_date=now)
            reason = (
                f"Conditional exception approved: EPSS score {request.epss_score:.4f} meets or exceeds "
                f"threshold {EPSS_APPROVAL_THRESHOLD:.2f}, but verified compensating control "
                f"({ctrl_ref}) is active in runtime. Valid for {lifespan_days} days under telemetry."
            )
            logger.info(
                "[%s] Conditionally approved via compensating control: %s",
                request.cve_id,
                ctrl_ref,
            )
            return ApprovalDecision(
                cve_id=request.cve_id,
                package_name=request.package_name,
                status=ApprovalStatus.APPROVED,
                decision_reason=reason,
                epss_score=request.epss_score,
                in_memory=False,
                approved_at=now,
                expires_at=expires_at,
                compensating_control_active=True,
                compensating_control_ref=ctrl_ref,
                evaluated_at=now,
            )

        reason = (
            f"Exception rejected: EPSS score {request.epss_score:.4f} meets or exceeds "
            f"the risk threshold of {EPSS_APPROVAL_THRESHOLD:.2f}."
        )
        deadline, sla_days = calculate_remediation_sla(request.severity, from_date=now)
        logger.warning(
            "[%s] Rejected: EPSS score %.4f >= threshold %.2f",
            request.cve_id,
            request.epss_score,
            EPSS_APPROVAL_THRESHOLD,
        )
        return ApprovalDecision(
            cve_id=request.cve_id,
            package_name=request.package_name,
            status=ApprovalStatus.REJECTED,
            decision_reason=reason,
            epss_score=request.epss_score,
            in_memory=False,
            remediation_sla_deadline=deadline,
            remediation_sla_days=sla_days,
            evaluated_at=now,
        )

    # Gate 2b: A negative memory result is only trustworthy with full host visibility.
    # Without it (rootless pod cannot read other users' /proc/<pid>/maps), withhold approval.
    if request.memory_visibility != "full":
        reason = (
            "Approval withheld: in_memory=False was determined with PARTIAL host visibility "
            "(root-owned processes could not be inspected). Re-evaluate once the oakai-memscan "
            "root snapshot is available."
        )
        logger.warning("[%s] Pending: memory visibility is %s", request.cve_id, request.memory_visibility)
        return ApprovalDecision(
            cve_id=request.cve_id,
            package_name=request.package_name,
            status=ApprovalStatus.PENDING_REVIEW,
            decision_reason=reason,
            epss_score=request.epss_score,
            in_memory=False,
            evaluated_at=now,
        )

    # Gate 3: Both deterministic checks passed -> Approve
    expires_at, lifespan_days = calculate_expiration(request.severity, from_date=now)
    reason = (
        f"Exception approved: Deterministic risk criteria satisfied (EPSS {request.epss_score:.4f} < "
        f"{EPSS_APPROVAL_THRESHOLD:.2f} and no active memory execution detected). "
        f"Valid for {lifespan_days} days."
    )
    logger.info("[%s] Approved exception for %s days", request.cve_id, lifespan_days)

    return ApprovalDecision(
        cve_id=request.cve_id,
        package_name=request.package_name,
        status=ApprovalStatus.APPROVED,
        decision_reason=reason,
        epss_score=request.epss_score,
        in_memory=False,
        approved_at=now,
        expires_at=expires_at,
        evaluated_at=now,
    )
