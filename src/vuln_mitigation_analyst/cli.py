"""Command-line interface for vuln-mitigation-analyst."""

import argparse
import logging
import sys

from .package_inspector import PackageInspector
from .rule_synthesizer import RuleSynthesizer
from .rule_validator import RuleValidator
from .schemas import MitigationRequest
from .socket_server import UdsMitigationServer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("vuln-mitigation-analyst")


def main():
    """CLI entrypoint for running daemon or testing rule generation."""
    parser = argparse.ArgumentParser(description="Vulnerability Mitigation Analyst CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # serve command
    serve_parser = subparsers.add_parser("serve", help="Run UDS mitigation daemon")
    serve_parser.add_argument(
        "--socket", default="/run/oakai/mitigate.sock", help="Path to UDS socket"
    )
    serve_parser.add_argument(
        "--approver-socket", default="/run/oakai/approve.sock", help="Downstream approver socket"
    )
    serve_parser.add_argument(
        "--rules-dir", default="/etc/falco/rules.d", help="Falco rules directory"
    )

    # generate command
    gen_parser = subparsers.add_parser("generate", help="Synthesize Falco rule for a CVE")
    gen_parser.add_argument("--cve", required=True, help="CVE ID (e.g. CVE-2024-38077)")
    gen_parser.add_argument("--package", required=True, help="Package name (e.g. libarchive13)")
    gen_parser.add_argument("--epss", type=float, default=0.85, help="EPSS exploit score")
    gen_parser.add_argument("--version", default="1.0.0", help="Installed version")

    args = parser.parse_args()

    if args.command == "serve":
        server = UdsMitigationServer(
            socket_path=args.socket,
            downstream_approve_socket=args.approver_socket,
            rules_dir=args.rules_dir,
        )
        try:
            server.start()
        except KeyboardInterrupt:
            server.stop()

    elif args.command == "generate":
        req = MitigationRequest(
            cve_id=args.cve,
            package_name=args.package,
            installed_version=args.version,
            epss_score=args.epss,
            ticket_path="",
        )
        inspector = PackageInspector()
        synthesizer = RuleSynthesizer()
        validator = RuleValidator()

        binaries = inspector.discover_binaries(req.package_name)
        rule = synthesizer.synthesize_rule(req, binaries)
        rule_yaml = synthesizer.render_yaml(rule)

        valid, msg = validator.validate_rule_yaml(rule_yaml)
        if not valid:
            logger.error("Validation failed: %s", msg)
            sys.exit(1)

        print(rule_yaml)


if __name__ == "__main__":
    main()
