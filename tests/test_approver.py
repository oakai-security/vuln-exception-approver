"""Unit test suite for vuln-exception-approver governance engine."""

import json
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

from vuln_exception_approver.decision_engine import evaluate_exception_request
from vuln_exception_approver.register_updater import (
    update_register_json,
    update_register_markdown,
    update_ticket_markdown,
)
from vuln_exception_approver.schemas import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStatus,
)
from vuln_exception_approver.sla_calculator import (
    calculate_expiration,
    calculate_remediation_sla,
)
from vuln_exception_approver.spike_monitor import (
    evaluate_epss_spike,
    fetch_live_epss_score,
)


def test_approval_decision_safe_high_severity():
    """Test approval of a safe vulnerability with High severity (30-day expiration)."""
    req = ApprovalRequest(
        cve_id="CVE-2024-38077",
        package_name="libarchive13",
        installed_version="3.6.2-1",
        severity="HIGH",
        epss_score=0.0004,
        in_memory=False,
        ticket_path="/tmp/test_ticket.md",
        justification="No upstream patch available; verified not resident in active memory.",
    )
    decision = evaluate_exception_request(req)
    assert decision.status == ApprovalStatus.APPROVED
    assert decision.in_memory is False
    assert decision.expires_at is not None
    assert decision.remediation_sla_deadline is None
    # Lifespan should be 30 days for HIGH severity
    expected_delta = timedelta(days=30)
    assert (decision.expires_at - decision.approved_at).days == expected_delta.days


def test_approval_decision_safe_medium_severity():
    """Test approval of a safe vulnerability with Medium severity (90-day expiration)."""
    req = ApprovalRequest(
        cve_id="CVE-2024-12345",
        package_name="tar",
        installed_version="1.34+dfsg-1",
        severity="MEDIUM",
        epss_score=0.0012,
        in_memory=False,
        ticket_path="/tmp/test_ticket.md",
        justification="Utility not running in memory; low exploit probability.",
    )
    decision = evaluate_exception_request(req)
    assert decision.status == ApprovalStatus.APPROVED
    assert (decision.expires_at - decision.approved_at).days == 90


def test_rejection_due_to_in_memory_execution():
    """Test rejection when vulnerable binary is mapped into active process memory."""
    req = ApprovalRequest(
        cve_id="CVE-2024-55555",
        package_name="openssl",
        installed_version="3.0.11-1",
        severity="CRITICAL",
        epss_score=0.0010,
        in_memory=True,  # Critical gate failure
        ticket_path="/tmp/test_ticket.md",
        justification="Core dependency.",
    )
    decision = evaluate_exception_request(req)
    assert decision.status == ApprovalStatus.REJECTED
    assert decision.in_memory is True
    assert "active system process memory" in decision.decision_reason
    assert decision.remediation_sla_days == 7
    assert decision.remediation_sla_deadline is not None


def test_rejection_due_to_high_epss_score():
    """Test rejection when EPSS score meets or exceeds 0.05 threshold."""
    req = ApprovalRequest(
        cve_id="CVE-2024-99999",
        package_name="curl",
        installed_version="7.88.1-10",
        severity="HIGH",
        epss_score=0.1550,  # 15.5% > 5.0% threshold
        in_memory=False,
        ticket_path="/tmp/test_ticket.md",
        justification="No update available.",
    )
    decision = evaluate_exception_request(req)
    assert decision.status == ApprovalStatus.REJECTED
    assert decision.epss_score == 0.1550
    assert "exceeds the risk threshold" in decision.decision_reason
    assert decision.remediation_sla_days == 14


def test_sla_calculator_matrix():
    """Test full SLA calculation matrix across severity levels."""
    base = datetime(2026, 11, 14, 12, 0, 0, tzinfo=UTC)

    # Expirations
    exp_crit, days_crit = calculate_expiration("CRITICAL", from_date=base)
    assert days_crit == 30
    assert exp_crit == base + timedelta(days=30)

    exp_med, days_med = calculate_expiration("MEDIUM", from_date=base)
    assert days_med == 90
    assert exp_med == base + timedelta(days=90)

    # Remediation SLAs
    rem_crit, rem_days_crit = calculate_remediation_sla("CRITICAL", from_date=base)
    assert rem_days_crit == 7
    assert rem_crit == base + timedelta(days=7)

    rem_high, rem_days_high = calculate_remediation_sla("HIGH", from_date=base)
    assert rem_days_high == 14

    rem_low, rem_days_low = calculate_remediation_sla("LOW", from_date=base)
    assert rem_days_low == 60


def test_epss_spike_revocation():
    """Test detection of an EPSS score spike above 0.05 triggering revocation."""
    decision = evaluate_epss_spike(
        cve_id="CVE-2024-38077",
        package_name="libarchive13",
        severity="HIGH",
        current_epss=0.0820,
        previous_epss=0.0004,
    )
    assert decision is not None
    assert decision.status == ApprovalStatus.REVOKED
    assert decision.remediation_sla_days == 14
    assert "Approval revoked due to EPSS spike" in decision.decision_reason

    # No revocation when score remains low
    no_spike = evaluate_epss_spike(
        cve_id="CVE-2024-38077",
        package_name="libarchive13",
        severity="HIGH",
        current_epss=0.0010,
        previous_epss=0.0004,
    )
    assert no_spike is None


def test_fetch_live_epss_score_mock(mocker):
    """Test querying live EPSS score with mocked response."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "status": "OK",
        "data": [{"cve": "CVE-2024-38077", "epss": "0.00045"}],
    }
    mocker.patch("requests.get", return_value=mock_resp)

    score = fetch_live_epss_score("CVE-2024-38077")
    assert score == 0.00045


def test_update_ticket_markdown(tmp_path):
    """Test updating Markdown ticket frontmatter and appending audit record."""
    ticket_file = tmp_path / "EXC-0001.md"
    initial_content = """---
id: EXC-0001
cve_id: CVE-2024-38077
package_name: libarchive13
status: pending_review
---

# Exception Ticket EXC-0001
"""
    ticket_file.write_text(initial_content, encoding="utf-8")

    decision = ApprovalDecision(
        cve_id="CVE-2024-38077",
        package_name="libarchive13",
        status=ApprovalStatus.APPROVED,
        decision_reason="Safe to approve",
        epss_score=0.0004,
        in_memory=False,
        approved_at=datetime(2026, 11, 14, 12, 0, 0, tzinfo=UTC),
        expires_at=datetime(2026, 12, 14, 12, 0, 0, tzinfo=UTC),
    )

    success = update_ticket_markdown(ticket_file, decision)
    assert success is True

    updated_text = ticket_file.read_text(encoding="utf-8")
    assert "status: approved" in updated_text
    assert "approval_status: APPROVED" in updated_text
    assert "expires_at: '2026-12-14'" in updated_text
    assert "## Governance Decision & Audit Record" in updated_text
    assert "Safe to approve" in updated_text


def test_update_register_json_and_markdown(tmp_path):
    """Test updating both JSON and Markdown register tables."""
    reg_json = tmp_path / "vulnerability_register.json"
    reg_md = tmp_path / "vulnerability_register.md"

    reg_md_content = """# Vulnerability Register

| CVE ID | Package | Version | Severity | EPSS | Status | Ticket | Expiration / SLA |
|---|---|---|---|---|---|---|---|
| CVE-2024-38077 | libarchive13 | 3.6.2-1 | HIGH | 0.0004 | PENDING_REVIEW | [EXC-0001](tickets/EXC-0001.md) | N/A |
"""
    reg_md.write_text(reg_md_content, encoding="utf-8")

    decision = ApprovalDecision(
        cve_id="CVE-2024-38077",
        package_name="libarchive13",
        status=ApprovalStatus.APPROVED,
        decision_reason="Safe risk profile",
        epss_score=0.0004,
        in_memory=False,
        approved_at=datetime(2026, 11, 14, 12, 0, 0, tzinfo=UTC),
        expires_at=datetime(2026, 12, 14, 12, 0, 0, tzinfo=UTC),
    )

    # Test JSON update
    assert update_register_json(reg_json, decision) is True
    data = json.loads(reg_json.read_text(encoding="utf-8"))
    assert len(data["vulnerabilities"]) == 1
    assert data["vulnerabilities"][0]["status"] == "APPROVED"
    assert data["vulnerabilities"][0]["expires_at"] == "2026-12-14"

    # Test Markdown update
    assert update_register_markdown(reg_md, decision) is True
    updated_md = reg_md.read_text(encoding="utf-8")
    assert "| CVE-2024-38077 | libarchive13 | 3.6.2-1 | HIGH | 0.0004 | APPROVED | [EXC-0001](tickets/EXC-0001.md) | 2026-12-14 |" in updated_md


def test_update_register_batch(tmp_path):
    """Test batch update of register JSON with multiple decisions."""
    from vuln_exception_approver.register_updater import update_register_batch_json

    reg_json = tmp_path / "vulnerability_register.json"
    decisions = [
        ApprovalDecision(
            cve_id=f"CVE-2024-{i:04d}",
            package_name=f"pkg-{i}",
            status=ApprovalStatus.APPROVED if i % 2 == 0 else ApprovalStatus.REJECTED,
            decision_reason="Batch decision",
            epss_score=0.001 * i,
            in_memory=False,
            approved_at=datetime(2026, 11, 14, 12, 0, 0, tzinfo=UTC),
            expires_at=datetime(2026, 12, 14, 12, 0, 0, tzinfo=UTC) if i % 2 == 0 else None,
            remediation_sla_deadline=datetime(2026, 11, 21, 12, 0, 0, tzinfo=UTC) if i % 2 != 0 else None,
        )
        for i in range(1, 5)
    ]

    assert update_register_batch_json(reg_json, decisions) is True
    data = json.loads(reg_json.read_text(encoding="utf-8"))
    assert data["total_tracked"] == 4
    assert data["active_exceptions"] == 2
    assert len(data["vulnerabilities"]) == 4


def test_compensating_control_approval():
    """Verify that a high-EPSS finding is conditionally approved when compensating control is active."""
    request = ApprovalRequest(
        cve_id="CVE-2024-38077",
        package_name="libarchive13",
        installed_version="3.6.2",
        severity="CRITICAL",
        epss_score=0.85,
        in_memory=False,
        ticket_path="/tmp/test.md",
        compensating_control_active=True,
        compensating_control_ref="falco_cve_2024_38077_mitigation",
        justification="Falco eBPF rule deployed",
    )
    decision = evaluate_exception_request(request)
    assert decision.status == ApprovalStatus.APPROVED
    assert decision.compensating_control_active is True
    assert "Conditional exception approved" in decision.decision_reason
    assert decision.expires_at is not None


def test_partial_memory_visibility_withholds_approval():
    """in_memory=False with partial host visibility must not be auto-approved."""
    from vuln_exception_approver.decision_engine import evaluate_exception_request
    from vuln_exception_approver.schemas import ApprovalRequest, ApprovalStatus

    req = ApprovalRequest(
        cve_id="CVE-2024-1111",
        package_name="wget",
        installed_version="1.0",
        severity="LOW",
        epss_score=0.001,
        in_memory=False,
        ticket_path="/tmp/x.md",
        justification="test",
        memory_visibility="partial",
    )
    assert evaluate_exception_request(req).status == ApprovalStatus.PENDING_REVIEW
    req_full = req.model_copy(update={"memory_visibility": "full"})
    assert evaluate_exception_request(req_full).status == ApprovalStatus.APPROVED
