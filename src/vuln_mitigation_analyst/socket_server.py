"""Unix Domain Socket server receiving rejected high-EPSS findings and deploying Falco mitigations."""

import contextlib
import json
import logging
import os
import socket
import struct
from pathlib import Path

from pydantic import ValidationError

from .deployer import RuleDeployer
from .package_inspector import PackageInspector
from .rule_synthesizer import RuleSynthesizer
from .rule_validator import RuleValidator
from .schemas import MitigationRequest, MitigationResult

logger = logging.getLogger(__name__)

DEFAULT_MITIGATE_SOCKET = os.environ.get("UDS_MITIGATE_SOCKET", "/run/oakai/mitigate.sock")
DEFAULT_APPROVE_SOCKET = os.environ.get("UDS_APPROVE_SOCKET", "/run/oakai/approve.sock")


class UdsMitigationServer:
    """UDS server that receives rejected findings, synthesizes Falco rules, and relays to approver."""

    def __init__(
        self,
        socket_path: str = DEFAULT_MITIGATE_SOCKET,
        downstream_approve_socket: str = DEFAULT_APPROVE_SOCKET,
        rules_dir: str | None = None,
    ):
        self.socket_path = socket_path
        self.downstream_socket = downstream_approve_socket
        self.inspector = PackageInspector()
        self.synthesizer = RuleSynthesizer()
        self.validator = RuleValidator()
        self.deployer = RuleDeployer(rules_dir=rules_dir) if rules_dir else RuleDeployer()
        self._running = False
        self._server_socket: socket.socket | None = None

    def start(self, max_connections: int = 5):
        """Bind UDS socket and listen for mitigation requests."""
        sock_file = Path(self.socket_path)
        sock_file.parent.mkdir(parents=True, exist_ok=True)

        if sock_file.exists():
            with contextlib.suppress(OSError):
                sock_file.unlink()

        self._server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server_socket.bind(self.socket_path)

        try:
            os.chmod(self.socket_path, 0o660)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        except OSError as err:
            logger.warning("Could not set socket permissions to 0660: %s", err)

        self._server_socket.listen(max_connections)
        self._running = True
        logger.info("vuln-mitigation-analyst listening on %s", self.socket_path)

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
        logger.info("vuln-mitigation-analyst stopped")

    def _handle_client(self, conn: socket.socket):
        """Process incoming rejected findings, deploy Falco rules, and relay to approver."""
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

                mitigation_results: list[MitigationResult] = []
                approval_payloads: list[dict] = []

                for item in items:
                    req = self._parse_request(item)
                    binaries = self.inspector.discover_binaries(req.package_name)
                    rule = self.synthesizer.synthesize_rule(req, binaries)
                    rule_yaml = self.synthesizer.render_yaml(rule)

                    valid, err_msg = self.validator.validate_rule_yaml(rule_yaml)
                    if not valid:
                        logger.error("Rule validation failed for %s: %s", req.cve_id, err_msg)
                        continue

                    result = self.deployer.deploy_rule(req, rule.rule, rule_yaml)
                    mitigation_results.append(result)

                    # Build payload for approver re-evaluation
                    approval_payloads.append(
                        {
                            "cve_id": req.cve_id,
                            "package_name": req.package_name,
                            "installed_version": req.installed_version,
                            "severity": "CRITICAL" if req.epss_score >= 0.5 else "HIGH",
                            "epss_score": req.epss_score,
                            "in_memory": False,
                            "ticket_path": req.ticket_path,
                            "compensating_control_active": True,
                            "compensating_control_ref": rule.rule,
                            "justification": f"Active Falco runtime eBPF compensating control deployed ({rule.rule})",
                        }
                    )

                # Forward conditionally mitigated findings to approver
                if approval_payloads and os.path.exists(self.downstream_socket):
                    self._forward_to_approver(approval_payloads)

                response = [r.model_dump(mode="json") for r in mitigation_results]
                conn.sendall(json.dumps(response, indent=2).encode("utf-8"))

            except (
                json.JSONDecodeError,
                ValidationError,
                KeyError,
                OSError,
                TypeError,
                ValueError,
            ) as err:
                logger.error("Error processing mitigation request: %s", err)
                conn.sendall(json.dumps({"error": str(err)}).encode("utf-8"))

    def _read_ticket_frontmatter(self, ticket_path_str: str) -> dict:
        """Read YAML frontmatter from an EXC-XXXX.md ticket on disk if available."""
        if not ticket_path_str:
            return {}
        candidates = [Path(ticket_path_str)]
        repo_path = os.environ.get("VULN_REGISTER_REPO", "/repo")
        candidates.append(Path(repo_path) / ticket_path_str)
        for p in candidates:
            if p.is_file():
                with contextlib.suppress(OSError):
                    lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
                    in_fm = False
                    data: dict = {"_resolved_path": str(p)}
                    for line in lines:
                        stripped = line.strip()
                        if stripped == "---":
                            if not in_fm:
                                in_fm = True
                                continue
                            break
                        if in_fm and ":" in stripped:
                            k, v = stripped.split(":", 1)
                            data[k.strip()] = v.strip().strip("'\"")
                    return data
        return {}

    def _parse_request(self, item: dict) -> MitigationRequest:
        """Normalize input dictionary into MitigationRequest model, hydrating from ticket on disk."""
        ticket_path = item.get("ticket_path", "")
        ticket_id = item.get("id", item.get("ticket_id", ""))
        if not ticket_path and ticket_id:
            ticket_path = f"tickets/{ticket_id}.md"

        fm = self._read_ticket_frontmatter(ticket_path)
        if "_resolved_path" in fm:
            ticket_path = fm["_resolved_path"]

        cve_id = item.get("cve_id") or fm.get("cve_id", "")
        pkg = item.get("package_name") or fm.get("package_name", "")
        ver = item.get("installed_version") or fm.get("installed_version", "unknown")

        raw_epss = item.get("epss_score", fm.get("epss_score", 0.0))
        try:
            epss = float(raw_epss)
        except (TypeError, ValueError):
            epss = 0.0

        raw_cvss = item.get("cvss_base", fm.get("cvss_base", 7.5))
        try:
            cvss = float(raw_cvss)
        except (TypeError, ValueError):
            cvss = 7.5

        return MitigationRequest(
            cve_id=cve_id,
            package_name=pkg,
            installed_version=ver,
            epss_score=epss,
            ticket_path=ticket_path,
            cvss_base=cvss,
            description=item.get("description") or fm.get("summary", ""),
            host=item.get("host") or fm.get("host", "lejeune"),
        )

    def _forward_to_approver(self, payloads: list[dict]):
        """Forward mitigated exception requests over UDS to vuln-exception-approver."""
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(self.downstream_socket)
                client.sendall(json.dumps(payloads).encode("utf-8"))
                client.shutdown(socket.SHUT_WR)
                client.recv(8192)
                logger.info("Forwarded %d mitigated tickets to approver socket", len(payloads))
        except OSError as err:
            logger.warning("Approver socket %s unreachable: %s", self.downstream_socket, err)

    def _get_peer_credentials(self, conn: socket.socket) -> str:
        """Inspect SO_PEERCRED on Linux."""
        try:
            creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            pid, uid, gid = struct.unpack("3i", creds)
            return f"PID={pid}, UID={uid}, GID={gid}"
        except (AttributeError, OSError):
            return "unknown (SO_PEERCRED unavailable)"
