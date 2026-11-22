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


def parse_ticket_frontmatter(ticket_path: Path) -> dict[str, Any]:
    """Read and parse YAML frontmatter from an actual Markdown exception ticket on disk."""
    if not ticket_path.exists():
        return {}

    try:
        content = ticket_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return {}

    lines = content.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}

    meta: dict[str, Any] = {}
    for line in lines[1:]:
        stripped = line.strip()
        if stripped == "---":
            break
        if ":" in stripped:
            key, val = stripped.split(":", 1)
            k = key.strip()
            v = val.strip().strip("'").strip('"')
            if v.lower() == "true":
                meta[k] = True
            elif v.lower() == "false":
                meta[k] = False
            else:
                try:
                    meta[k] = float(v) if "." in v else int(v)
                except ValueError:
                    meta[k] = v
    return meta


def update_ticket_markdown(ticket_path: Path, decision: ApprovalDecision) -> bool:
    """Update ONLY the YAML frontmatter and audit log of a Markdown exception ticket."""
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
    frontmatter_done = False
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

    leaked_keys = (
        "approval_status:",
        "approver:",
        "evaluated_at:",
        "expires_at:",
        "remediation_deadline:",
    )

    for line in lines:
        if line.strip() == "---" and not frontmatter_done:
            if not in_frontmatter:
                in_frontmatter = True
                new_lines.append(line)
                continue
            else:
                in_frontmatter = False
                frontmatter_done = True
                # Inject updated frontmatter keys before closing frontmatter delimiter
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
            if line.strip().startswith("status:"):
                if decision.status == ApprovalStatus.APPROVED:
                    mapped_status = "approved"
                elif decision.status == ApprovalStatus.PENDING_REVIEW:
                    mapped_status = "pending_review"
                else:
                    mapped_status = "remediation_required"
                new_lines.append(f"status: {mapped_status}")
                continue
            if line.strip().startswith(leaked_keys):
                continue
        else:
            # Clean up any previously leaked YAML keys in the Markdown body
            if line.strip().startswith(leaked_keys) or line.strip().startswith(
                ("compensating_control_active:", "compensating_control_ref:", "compensating_control_file:")
            ):
                continue

        new_lines.append(line)

    # Strip any prior Governance Decision & Audit Record section before appending latest decision
    cleaned_lines: list[str] = []
    skip_section = False
    for line in new_lines:
        if line.strip() == "## Governance Decision & Audit Record":
            skip_section = True
            continue
        if skip_section and line.startswith("## "):
            skip_section = False
        if not skip_section:
            cleaned_lines.append(line)

    while cleaned_lines and not cleaned_lines[-1].strip():
        cleaned_lines.pop()

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

    updated_content = "\n".join(cleaned_lines) + "\n" + "\n".join(audit_section) + "\n"

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
    return update_register_batch_json(register_json_path, [decision])


def update_register_batch_json(
    register_json_path: Path, decisions: list[ApprovalDecision]
) -> bool:
    """Update multiple entries in vulnerability_register.json in a single atomic write."""
    if not decisions:
        return True

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

    for decision in decisions:
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

        entry_found = False
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
                entry["expiration"] = expires_str or deadline_str or "N/A"
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
                    "expiration": expires_str or deadline_str or "N/A",
                    "remediation_deadline": deadline_str,
                }
            )

    register_data["vulnerabilities"] = vulns
    register_data["last_updated"] = _utc_now().isoformat()
    register_data["total_tracked"] = len(vulns)
    register_data["active_exceptions"] = sum(
        1 for v in vulns if v.get("status") == "APPROVED"
    )
    register_data["pending_review"] = sum(
        1 for v in vulns if v.get("status") == "PENDING_REVIEW"
    )

    try:
        register_json_path.parent.mkdir(parents=True, exist_ok=True)
        register_json_path.write_text(
            json.dumps(register_data, indent=2) + "\n", encoding="utf-8"
        )
        logger.info("Updated register JSON with %d decisions", len(decisions))
        return True
    except OSError as err:
        logger.error("Failed to write register JSON %s: %s", register_json_path, err)
        return False


def update_register_markdown(
    register_md_path: Path, decision: ApprovalDecision
) -> bool:
    """Update Markdown register table with approval decision."""
    return update_register_batch_markdown(register_md_path, [decision])


def update_register_batch_markdown(
    register_md_path: Path, decisions: list[ApprovalDecision]
) -> bool:
    """Update Markdown register table with multiple approval decisions."""
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
    any_updated = False

    decision_map = {(d.cve_id, d.package_name): d for d in decisions}

    for line in lines:
        matched = False
        for (cve, pkg), decision in decision_map.items():
            pattern_plain = f"| {cve} | {pkg} |"
            pattern_ticks = f"| `{cve}` | `{pkg}` |"

            deadline_str = (
                decision.expires_at.strftime("%Y-%m-%d")
                if decision.expires_at
                else (
                    decision.remediation_sla_deadline.strftime("%Y-%m-%d")
                    if decision.remediation_sla_deadline
                    else "N/A"
                )
            )

            if line.startswith(pattern_plain):
                cols = [c.strip() for c in line.split("|")[1:-1]]
                if len(cols) >= 8:
                    cols[5] = decision.status.value
                    cols[7] = deadline_str
                    new_lines.append("| " + " | ".join(cols) + " |")
                    matched = True
                    any_updated = True
                    break
            elif line.startswith(pattern_ticks):
                cols = [c.strip() for c in line.split("|")[1:-1]]
                if len(cols) >= 9:
                    cols[7] = f"**{decision.status.value}**"
                    cols[8] = f"`{deadline_str}`"
                    new_lines.append("| " + " | ".join(cols) + " |")
                    matched = True
                    any_updated = True
                    break

        if not matched:
            new_lines.append(line)

    if any_updated:
        try:
            register_md_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
            logger.info("Updated register Markdown with %d decisions", len(decisions))
            return True
        except OSError as err:
            logger.error("Failed to write register Markdown %s: %s", register_md_path, err)
            return False

    return False
