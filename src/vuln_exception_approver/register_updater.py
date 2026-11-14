"""Vulnerability register and ticket updater for exception approvals and rejections."""

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from vuln_exception_approver.schemas import ApprovalDecision, ApprovalStatus

logger = logging.getLogger(__name__)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def update_ticket_markdown(ticket_path: Path, decision: ApprovalDecision) -> bool:
    """Update the frontmatter and audit log of a Markdown exception ticket."""
    if not ticket_path.exists():
        logger.error("Ticket file does not exist: %s", ticket_path)
        return False

    try:
        content = ticket_path.read_text(encoding="utf-8")
    except OSError as err:
        logger.error("Failed to read ticket %s: %s", ticket_path, err)
        return False

    lines = content.splitlines()
    in_frontmatter = False
    new_lines: list[str] = []

    expires_str = (
        decision.expires_at.strftime("%Y-%m-%d")
        if decision.expires_at
        else ""
    )
    deadline_str = (
        decision.remediation_sla_deadline.strftime("%Y-%m-%d")
        if decision.remediation_sla_deadline
        else ""
    )

    for line in lines:
        if line.strip() == "---":
            if not in_frontmatter:
                in_frontmatter = True
                new_lines.append(line)
                continue
            else:
                in_frontmatter = False
                # Inject updated frontmatter keys before closing delimiter
                new_lines.append(f"approval_status: {decision.status.value}")
                new_lines.append("approver: vuln-exception-approver")
                new_lines.append(
                    f"evaluated_at: {decision.evaluated_at.isoformat()}"
                )
                if expires_str:
                    new_lines.append(f"expires_at: '{expires_str}'")
                if deadline_str:
                    new_lines.append(f"remediation_deadline: '{deadline_str}'")
                new_lines.append(line)
                continue

        if in_frontmatter:
            # Update status key in frontmatter if present
            if line.strip().startswith("status:"):
                mapped_status = (
                    "approved"
                    if decision.status == ApprovalStatus.APPROVED
                    else "remediation_required"
                )
                new_lines.append(f"status: {mapped_status}")
                continue
            if line.strip().startswith(
                ("approval_status:", "approver:", "evaluated_at:", "expires_at:", "remediation_deadline:")
            ):
                # Skip older injected keys
                continue

        new_lines.append(line)

    # Append Governance Review Audit Section
    audit_section = [
        "",
        "## Governance Decision & Audit Record",
        f"- **Decision**: `{decision.status.value}`",
        f"- **Evaluated By**: `{decision.evaluated_by}`",
        f"- **Evaluated At**: `{decision.evaluated_at.isoformat()}`",
        f"- **Reason**: {decision.decision_reason}",
        f"- **EPSS Score**: `{decision.epss_score:.4f}`",
        f"- **In-Memory Execution**: `{decision.in_memory}`",
    ]

    if decision.expires_at:
        audit_section.append(f"- **Expiration Date**: `{expires_str}`")
    if decision.remediation_sla_deadline:
        audit_section.append(
            f"- **Mandatory Remediation SLA Deadline**: `{deadline_str}` ({decision.remediation_sla_days} days)"
        )

    updated_content = "\n".join(new_lines) + "\n" + "\n".join(audit_section) + "\n"

    try:
        ticket_path.write_text(updated_content, encoding="utf-8")
        logger.info("Updated exception ticket: %s", ticket_path)
        return True
    except OSError as err:
        logger.error("Failed to write updated ticket %s: %s", ticket_path, err)
        return False


def update_register_json(
    register_json_path: Path, decision: ApprovalDecision
) -> bool:
    """Update entry in vulnerability_register.json."""
    if not register_json_path.exists():
        logger.warning(
            "Register JSON not found at %s. Creating new register.",
            register_json_path,
        )
        register_data: dict[str, Any] = {
            "version": "1.0.0",
            "last_updated": _utc_now().isoformat(),
            "vulnerabilities": [],
        }
    else:
        try:
            register_data = json.loads(
                register_json_path.read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as err:
            logger.error(
                "Failed to parse register JSON %s: %s", register_json_path, err
            )
            return False

    vulns: list[dict[str, Any]] = register_data.get("vulnerabilities", [])
    entry_found = False

    expires_str = (
        decision.expires_at.strftime("%Y-%m-%d")
        if decision.expires_at
        else None
    )
    deadline_str = (
        decision.remediation_sla_deadline.strftime("%Y-%m-%d")
        if decision.remediation_sla_deadline
        else None
    )

    for entry in vulns:
        if (
            entry.get("cve_id") == decision.cve_id
            and entry.get("package_name") == decision.package_name
        ):
            entry["status"] = decision.status.value
            entry["evaluated_by"] = decision.evaluated_by
            entry["evaluated_at"] = decision.evaluated_at.isoformat()
            entry["decision_reason"] = decision.decision_reason
            entry["expires_at"] = expires_str
            entry["remediation_deadline"] = deadline_str
            entry_found = True
            break

    if not entry_found:
        vulns.append(
            {
                "cve_id": decision.cve_id,
                "package_name": decision.package_name,
                "status": decision.status.value,
                "epss_score": decision.epss_score,
                "in_memory": decision.in_memory,
                "evaluated_by": decision.evaluated_by,
                "evaluated_at": decision.evaluated_at.isoformat(),
                "decision_reason": decision.decision_reason,
                "expires_at": expires_str,
                "remediation_deadline": deadline_str,
            }
        )

    register_data["vulnerabilities"] = vulns
    register_data["last_updated"] = _utc_now().isoformat()

    try:
        register_json_path.parent.mkdir(parents=True, exist_ok=True)
        register_json_path.write_text(
            json.dumps(register_data, indent=2) + "\n", encoding="utf-8"
        )
        logger.info("Updated register JSON at %s", register_json_path)
        return True
    except OSError as err:
        logger.error("Failed to write register JSON %s: %s", register_json_path, err)
        return False


def update_register_markdown(
    register_md_path: Path, decision: ApprovalDecision
) -> bool:
    """Update Markdown register table with approval decision."""
    if not register_md_path.exists():
        logger.warning(
            "Register Markdown not found at %s. Skipping Markdown update.",
            register_md_path,
        )
        return False

    try:
        content = register_md_path.read_text(encoding="utf-8")
    except OSError as err:
        logger.error("Failed to read register Markdown %s: %s", register_md_path, err)
        return False

    lines = content.splitlines()
    new_lines: list[str] = []
    updated = False

    target_pattern = f"| {decision.cve_id} | {decision.package_name} |"
    deadline_str = (
        decision.expires_at.strftime("%Y-%m-%d")
        if decision.expires_at
        else (
            decision.remediation_sla_deadline.strftime("%Y-%m-%d")
            if decision.remediation_sla_deadline
            else "N/A"
        )
    )

    for line in lines:
        if line.startswith(target_pattern):
            # Parse existing columns
            cols = [c.strip() for c in line.split("|")[1:-1]]
            if len(cols) >= 8:
                # Update status and expiration/deadline columns
                cols[5] = decision.status.value
                cols[7] = deadline_str
                new_line = "| " + " | ".join(cols) + " |"
                new_lines.append(new_line)
                updated = True
                continue
        new_lines.append(line)

    if updated:
        try:
            register_md_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
            logger.info("Updated register Markdown at %s", register_md_path)
            return True
        except OSError as err:
            logger.error("Failed to write register Markdown %s: %s", register_md_path, err)
            return False

    return False
