"""Unix Domain Socket server executing deterministic risk governance and exception decisions."""

import contextlib
import json
import logging
import os
import socket
import struct
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from vuln_exception_approver.decision_engine import evaluate_exception_request
from vuln_exception_approver.git_manager import GitManager
from vuln_exception_approver.register_updater import (
    parse_ticket_frontmatter,
    update_register_batch_json,
    update_register_batch_markdown,
    update_ticket_markdown,
)
from vuln_exception_approver.schemas import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStatus,
)

logger = logging.getLogger(__name__)

DEFAULT_APPROVE_SOCKET = os.environ.get("UDS_APPROVE_SOCKET", "/run/oakai/approve.sock")
DEFAULT_MITIGATE_SOCKET = os.environ.get("UDS_MITIGATE_SOCKET", "/run/oakai/mitigate.sock")
DEFAULT_REGISTER_REPO = os.environ.get(
    "VULN_REGISTER_PATH", "/home/curt/dev/repos/vuln-register"
)


class UdsApproverServer:
    """UDS server that receives exception requests, reads tickets, evaluates gates, and updates register."""

    def __init__(
        self,
        socket_path: str = DEFAULT_APPROVE_SOCKET,
        mitigate_socket_path: str = DEFAULT_MITIGATE_SOCKET,
        register_repo_path: str = DEFAULT_REGISTER_REPO,
        auto_push: bool = False,
    ):
        self.socket_path = socket_path
        self.mitigate_socket_path = mitigate_socket_path
        self.repo_dir = Path(register_repo_path)
        self.git_manager = GitManager(self.repo_dir, auto_push=auto_push)
        self._running = False
        self._server_socket: socket.socket | None = None

    def start(self, max_connections: int = 5):
        """Bind UDS socket and process incoming approval requests."""
        sock_file = Path(self.socket_path)
        sock_file.parent.mkdir(parents=True, exist_ok=True)

        if sock_file.exists():
            try:
                sock_file.unlink()
            except OSError as err:
                logger.warning("Failed to unlink stale socket: %s", err)

        self._server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server_socket.bind(self.socket_path)

        try:
            os.chmod(self.socket_path, 0o660)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        except OSError as err:
            logger.warning("Could not set socket permissions to 0660: %s", err)

        self._server_socket.listen(max_connections)
        self._running = True
        logger.info("vuln-exception-approver listening on %s", self.socket_path)

        while self._running:
            try:
                conn, _ = self._server_socket.accept()
                self._handle_client(conn)
            except (OSError, KeyboardInterrupt) as err:
                if self._running:
                    logger.error("Socket error: %s", err)
                break

    def stop(self):
        """Stop server and clean up socket file."""
        self._running = False
        if self._server_socket:
            with contextlib.suppress(OSError):
                self._server_socket.close()
        if os.path.exists(self.socket_path):
            with contextlib.suppress(OSError):
                os.unlink(self.socket_path)
        logger.info("vuln-exception-approver stopped")

    def _handle_client(self, conn: socket.socket):
        """Process incoming requests, evaluate governance gates, update register, and reply."""
        rejected_for_mitigation: list[dict[str, Any]] = []

        with conn:
            peer_info = self._get_peer_credentials(conn)
            logger.info("Accepted connection from: %s", peer_info)

            buffer = []
            while True:
                chunk = conn.recv(8192)
                if not chunk:
                    break
                buffer.append(chunk.decode("utf-8", errors="ignore"))

            raw_body = "".join(buffer).strip()
            if not raw_body:
                return

            try:
                parsed = json.loads(raw_body)
                items = parsed if isinstance(parsed, list) else [parsed]

                decisions: list[ApprovalDecision] = []
                for item in items:
                    decision, mit_payload = self._process_single_request(item)
                    if decision:
                        decisions.append(decision)
                    if mit_payload:
                        rejected_for_mitigation.append(mit_payload)

                if decisions:
                    register_json = self.repo_dir / "register" / "vulnerability_register.json"
                    register_md = self.repo_dir / "register" / "vulnerability_register.md"
                    update_register_batch_json(register_json, decisions)
                    update_register_batch_markdown(register_md, decisions)

                    approved_count = sum(
                        1 for d in decisions if d.status == ApprovalStatus.APPROVED
                    )
                    rejected_count = len(decisions) - approved_count
                    commit_msg = (
                        f"chore(governance): processed {len(decisions)} decisions "
                        f"({approved_count} approved, {rejected_count} rejected)"
                    )
                    self.git_manager.commit_batch(commit_msg)

                response = [d.model_dump(mode="json") for d in decisions]
                conn.sendall(json.dumps(response, indent=2).encode("utf-8"))

            except (
                json.JSONDecodeError,
                ValidationError,
                KeyError,
                OSError,
                TypeError,
                ValueError,
            ) as err:
                logger.error("Error processing approval request: %s", err)
                conn.sendall(json.dumps({"error": str(err)}).encode("utf-8"))

        # Asynchronously dispatch rejected non-in-memory high-EPSS tickets to mitigation analyst
        if rejected_for_mitigation and os.path.exists(self.mitigate_socket_path):
            threading.Thread(
                target=self._forward_to_mitigation,
                args=(rejected_for_mitigation,),
                daemon=True,
            ).start()

    def _resolve_ticket_path(
        self, item: dict[str, Any], cve_id: str, pkg: str
    ) -> Path:
        """Resolve full path to the actual EXC-XXXX.md ticket file on disk."""
        ticket_id = str(item.get("id", item.get("ticket_id", ""))).strip()
        rel_ticket_path = str(item.get("ticket_path", "")).strip()

        if rel_ticket_path:
            p = Path(rel_ticket_path)
            if p.is_absolute() and p.exists():
                return p
            cand = self.repo_dir / rel_ticket_path.lstrip("/")
            if cand.exists():
                return cand

        if ticket_id:
            cand = self.repo_dir / "tickets" / f"{ticket_id}.md"
            if cand.exists():
                return cand

        # Search register or tickets dir for matching (cve_id, package_name)
        tickets_dir = self.repo_dir / "tickets"
        if tickets_dir.exists() and cve_id and pkg:
            for f in sorted(tickets_dir.glob("EXC-*.md")):
                meta = parse_ticket_frontmatter(f)
                if meta.get("cve_id") == cve_id and meta.get("package_name") == pkg:
                    return f

        return (
            self.repo_dir / rel_ticket_path
            if rel_ticket_path
            else self.repo_dir / f"tickets/{ticket_id or 'EXC-0000'}.md"
        )

    def _process_single_request(
        self, item: dict[str, Any]
    ) -> tuple[ApprovalDecision, dict[str, Any] | None]:
        """Read actual ticket frontmatter from disk, evaluate decision, and apply updates."""
        cve_id = str(item.get("cve_id", ""))
        pkg = str(item.get("package_name", ""))
        full_ticket_path = self._resolve_ticket_path(item, cve_id, pkg)

        # Read ground-truth attributes from actual ticket file on disk if present
        ticket_meta = parse_ticket_frontmatter(full_ticket_path)
        if ticket_meta:
            logger.info(
                "Read actual ticket file %s for %s (%s)",
                full_ticket_path.name,
                ticket_meta.get("cve_id", cve_id),
                ticket_meta.get("package_name", pkg),
            )

        cve_id = str(cve_id or ticket_meta.get("cve_id", ""))
        pkg = str(pkg or ticket_meta.get("package_name", ""))
        installed_ver = str(
            item.get("installed_version")
            or ticket_meta.get("installed_version", "unknown")
        )
        severity = str(
            item.get("severity")
            or item.get("threat_level")
            or ticket_meta.get("threat_level", "MEDIUM")
        )
        epss = float(
            item.get("epss_score")
            if "epss_score" in item
            else ticket_meta.get("epss_score", 0.0)
        )
        in_mem = bool(
            item.get("in_memory")
            if "in_memory" in item
            else ticket_meta.get("in_memory", False)
        )
        mem_visibility = str(
            item.get("memory_visibility")
            or ticket_meta.get("memory_visibility", "partial")
        )
        comp_active = bool(
            item.get("compensating_control_active")
            if "compensating_control_active" in item
            else ticket_meta.get("compensating_control_active", False)
        )
        comp_ref = (
            item.get("compensating_control_ref")
            or ticket_meta.get("compensating_control_ref", None)
        )
        if comp_ref is not None:
            comp_ref = str(comp_ref)

        justification = str(
            item.get("justification")
            or item.get("reason")
            or item.get("remediation_attempt_summary")
            or "Automated remediation attempted"
        )

        request = ApprovalRequest(
            cve_id=cve_id,
            package_name=pkg,
            installed_version=installed_ver,
            severity=severity,
            epss_score=epss,
            in_memory=in_mem,
            memory_visibility=mem_visibility,
            ticket_path=str(full_ticket_path),
            compensating_control_active=comp_active,
            compensating_control_ref=comp_ref,
            justification=justification,
            requested_at=datetime.now(UTC),
        )

        decision = evaluate_exception_request(request)

        if full_ticket_path.exists():
            update_ticket_markdown(full_ticket_path, decision)

        mit_payload = None
        if (
            decision.status == ApprovalStatus.REJECTED
            and not in_mem
            and epss >= 0.05
            and not comp_active
        ):
            mit_payload = {
                "cve_id": cve_id,
                "package_name": pkg,
                "installed_version": installed_ver,
                "epss_score": epss,
                "ticket_path": str(full_ticket_path),
            }

        return decision, mit_payload

    def _forward_to_mitigation(self, payloads: list[dict[str, Any]]):
        """Route rejected high-EPSS non-in-memory tickets to vuln-mitigation-analyst."""
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(self.mitigate_socket_path)
                client.sendall(json.dumps(payloads).encode("utf-8"))
                client.shutdown(socket.SHUT_WR)
                client.recv(8192)
                logger.info(
                    "Auto-forwarded %d rejected high-EPSS tickets to mitigation analyst",
                    len(payloads),
                )
        except OSError as err:
            logger.warning(
                "Mitigation socket %s unreachable: %s",
                self.mitigate_socket_path,
                err,
            )

    def _get_peer_credentials(self, conn: socket.socket) -> str:
        """Inspect SO_PEERCRED on Linux."""
        try:
            creds = conn.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
            )
            pid, uid, gid = struct.unpack("3i", creds)
            return f"PID={pid}, UID={uid}, GID={gid}"
        except (AttributeError, OSError):
            return "unknown (SO_PEERCRED unavailable)"
