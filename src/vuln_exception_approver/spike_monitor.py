"""Daily EPSS spike monitor for actively approved vulnerability exceptions."""

import logging
from datetime import UTC, datetime

import requests

from vuln_exception_approver.schemas import ApprovalDecision, ApprovalStatus
from vuln_exception_approver.sla_calculator import calculate_remediation_sla

logger = logging.getLogger(__name__)

FIRST_EPSS_API_URL = "https://api.first.org/data/v1/epss"
REVOCATION_EPSS_THRESHOLD = 0.05


def fetch_live_epss_score(cve_id: str, timeout: int = 10) -> float | None:
    """Fetch live EPSS score from FIRST.org API."""
    params = {"cve": cve_id}
    headers = {"User-Agent": "vuln-exception-approver/1.0 (Oakai-Security)"}

    try:
        response = requests.get(
            FIRST_EPSS_API_URL, params=params, headers=headers, timeout=timeout
        )
        if response.status_code != 200:
            logger.warning(
                "FIRST.org EPSS API returned status code %s for %s",
                response.status_code,
                cve_id,
            )
            return None

        data = response.json()
        entries = data.get("data", [])
        if not entries:
            logger.warning("No EPSS score found for %s", cve_id)
            return None

        score_str = entries[0].get("epss")
        if score_str is not None:
            return float(score_str)

    except (requests.RequestException, ValueError, KeyError) as err:
        logger.error("Error querying EPSS API for %s: %s", cve_id, err)

    return None


def evaluate_epss_spike(
    cve_id: str,
    package_name: str,
    severity: str,
    current_epss: float,
    previous_epss: float,
) -> ApprovalDecision | None:
    """Evaluate whether an EPSS spike warrants immediate revocation.

    If current EPSS >= 0.05, approval is revoked and a 7-day SLA is initiated.
    """
    now = datetime.now(UTC)

    if current_epss >= REVOCATION_EPSS_THRESHOLD:
        reason = (
            f"Approval revoked due to EPSS spike: Score rose from {previous_epss:.4f} "
            f"to {current_epss:.4f}, exceeding the safe threshold of {REVOCATION_EPSS_THRESHOLD:.2f}."
        )
        deadline, sla_days = calculate_remediation_sla(severity, from_date=now)
        logger.warning(
            "[%s] SPIKE DETECTED: EPSS rose to %.4f. Revoking approval.",
            cve_id,
            current_epss,
        )

        return ApprovalDecision(
            cve_id=cve_id,
            package_name=package_name,
            status=ApprovalStatus.REVOKED,
            decision_reason=reason,
            epss_score=current_epss,
            in_memory=False,
            remediation_sla_deadline=deadline,
            remediation_sla_days=sla_days,
            evaluated_at=now,
        )

    return None


def check_active_exceptions_for_spikes(
    active_exceptions: list[dict[str, str]],
) -> list[ApprovalDecision]:
    """Check a list of active exceptions and return decisions for any spiked CVEs."""
    revocations: list[ApprovalDecision] = []

    for item in active_exceptions:
        cve_id = item.get("cve_id", "")
        pkg = item.get("package_name", "unknown")
        severity = item.get("severity", "MEDIUM")
        prev_epss_raw = item.get("epss_score", "0.0")

        try:
            prev_epss = float(prev_epss_raw)
        except ValueError:
            prev_epss = 0.0

        if not cve_id:
            continue

        live_epss = fetch_live_epss_score(cve_id)
        if live_epss is None:
            continue

        decision = evaluate_epss_spike(
            cve_id=cve_id,
            package_name=pkg,
            severity=severity,
            current_epss=live_epss,
            previous_epss=prev_epss,
        )
        if decision:
            revocations.append(decision)

    return revocations
