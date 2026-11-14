"""Command-line interface for vuln-exception-approver."""

import argparse
import json
import logging
import sys
from pathlib import Path

from vuln_exception_approver.decision_engine import evaluate_exception_request
from vuln_exception_approver.schemas import ApprovalRequest
from vuln_exception_approver.socket_server import (
    DEFAULT_APPROVE_SOCKET,
    DEFAULT_REGISTER_REPO,
    UdsApproverServer,
)
from vuln_exception_approver.spike_monitor import check_active_exceptions_for_spikes

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("vuln-exception-approver")


def cmd_serve(args: argparse.Namespace) -> int:
    """Start the UDS approval server daemon."""
    server = UdsApproverServer(
        socket_path=args.socket,
        register_repo_path=args.register_repo,
        auto_push=args.push,
    )
    try:
        server.start()
    except KeyboardInterrupt:
        logger.info("Shutdown requested")
    finally:
        server.stop()
    return 0


def cmd_review_single(args: argparse.Namespace) -> int:
    """Evaluate a single exception request payload from stdin or file."""
    if args.input_file:
        raw_text = Path(args.input_file).read_text(encoding="utf-8")
    else:
        raw_text = sys.stdin.read()

    data = json.loads(raw_text)
    request = ApprovalRequest.model_validate(data)
    decision = evaluate_exception_request(request)

    print(json.dumps(decision.model_dump(mode="json"), indent=2))
    return 0 if decision.status.value == "APPROVED" else 1


def cmd_check_spikes(args: argparse.Namespace) -> int:
    """Scan active approved exceptions in vuln-register and revoke spiked CVEs."""
    register_json_path = (
        Path(args.register_repo) / "register" / "vulnerability_register.json"
    )
    if not register_json_path.exists():
        logger.error("Register JSON file not found at %s", register_json_path)
        return 1

    data = json.loads(register_json_path.read_text(encoding="utf-8"))
    vulns = data.get("vulnerabilities", [])

    # Filter for active APPROVED exceptions
    approved_vulns = [v for v in vulns if v.get("status") == "APPROVED"]
    logger.info("Found %d active approved exceptions to audit", len(approved_vulns))

    revocations = check_active_exceptions_for_spikes(approved_vulns)
    if not revocations:
        logger.info("Audit complete: No EPSS spikes detected across active exceptions.")
        return 0

    logger.warning("Spike audit complete: %d exceptions revoked", len(revocations))
    for r in revocations:
        print(f"REVOKED: {r.cve_id} ({r.package_name}) - EPSS: {r.epss_score:.4f}")
    return 2


def build_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="vuln-exception-approver",
        description="Deterministic risk governance and vulnerability exception approval micro-agent.",
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # serve command
    serve_parser = subparsers.add_parser("serve", help="Run UDS server daemon")
    serve_parser.add_argument(
        "--socket",
        default=DEFAULT_APPROVE_SOCKET,
        help=f"UDS socket path (default: {DEFAULT_APPROVE_SOCKET})",
    )
    serve_parser.add_argument(
        "--register-repo",
        default=DEFAULT_REGISTER_REPO,
        help="Path to vuln-register repository",
    )
    serve_parser.add_argument(
        "--push",
        action="store_true",
        help="Automatically push git commits to remote repository",
    )
    serve_parser.set_defaults(func=cmd_serve)

    # review-single command
    review_parser = subparsers.add_parser(
        "review-single", help="Evaluate single exception request"
    )
    review_parser.add_argument(
        "--input-file", "-f", help="Path to JSON file (reads stdin if omitted)"
    )
    review_parser.set_defaults(func=cmd_review_single)

    # check-spikes command
    spike_parser = subparsers.add_parser(
        "check-spikes", help="Audit active approved exceptions for EPSS spikes"
    )
    spike_parser.add_argument(
        "--register-repo",
        default=DEFAULT_REGISTER_REPO,
        help="Path to vuln-register repository",
    )
    spike_parser.set_defaults(func=cmd_check_spikes)

    return parser


def main() -> int:
    """Main CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
