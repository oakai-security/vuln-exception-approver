"""Unix Domain Socket server executing deterministic risk governance and exception decisions."""

import contextlib
import json
import logging
import os
import socket
import struct
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from vuln_exception_approver.decision_engine import evaluate_exception_request
from vuln_exception_approver.git_manager import GitManager
from vuln_exception_approver.register_updater import (
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
DEFAULT_REGISTER_REPO = os.environ.get(
    "VULN_REGISTER_PATH", "/home/curt/dev/repos/vuln-register"
)


class UdsApproverServer:
    """UDS server that receives exception requests, evaluates risk gates, and updates register."""

    def __init__(
        self,
        socket_path: str = DEFAULT_APPROVE_SOCKET,
        register_repo_path: str = DEFAULT_REGISTER_REPO,
        auto_push: bool = False,
    ):
        self.socket_path = socket_path
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
                    decision = self._process_single_request(item)
                    if decision:
                        decisions.append(decision)

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

    def _process_single_request(self, item: dict[str, Any]) -> ApprovalDecision:
        """Parse item into ApprovalRequest, evaluate decision, and apply updates."""
        # Normalize input whether from ExceptionTicket or direct ApprovalRequest
        cve_id = item.get("cve_id", "")
        pkg = item.get("package_name", "")
        installed_ver = item.get("installed_version", "unknown")
        severity = item.get("severity", item.get("threat_level", "MEDIUM"))
        epss = float(item.get("epss_score", 0.0))
        in_mem = bool(item.get("in_memory", False))

        ticket_id = item.get("id", item.get("ticket_id", ""))
        rel_ticket_path = item.get("ticket_path", "")
        if not rel_ticket_path and ticket_id:
            rel_ticket_path = f"tickets/{ticket_id}.md"

        full_ticket_path = (
            self.repo_dir / rel_ticket_path
            if rel_ticket_path
            else self.repo_dir / f"tickets/{ticket_id}.md"
        )
        justification = item.get(
            "justification",
            item.get("remediation_attempt_summary", "Automated remediation attempted"),
        )

        request = ApprovalRequest(
            cve_id=cve_id,
            package_name=pkg,
            installed_version=installed_ver,
            severity=severity,
            epss_score=epss,
            in_memory=in_mem,
            ticket_path=str(full_ticket_path),
            justification=justification,
            requested_at=datetime.now(UTC),
        )

        decision = evaluate_exception_request(request)

        # Update ticket markdown
        if full_ticket_path.exists():
            update_ticket_markdown(full_ticket_path, decision)

        return decision

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
