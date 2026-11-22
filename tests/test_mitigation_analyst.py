"""Unit test suite for vuln-mitigation-analyst micro-agent."""

import json
import socket
import tempfile
import threading
from pathlib import Path

from vuln_mitigation_analyst.deployer import RuleDeployer
from vuln_mitigation_analyst.package_inspector import PackageInspector
from vuln_mitigation_analyst.rule_synthesizer import RuleSynthesizer
from vuln_mitigation_analyst.rule_validator import RuleValidator
from vuln_mitigation_analyst.schemas import FalcoPriority, MitigationRequest
from vuln_mitigation_analyst.socket_server import UdsMitigationServer


def test_package_inspector_known_mapping():
    """Verify package inspector returns mapped binaries for archive and container packages."""
    inspector = PackageInspector()
    archive_bins = inspector.discover_binaries("libarchive13")
    assert "bsdtar" in archive_bins
    assert "tar" in archive_bins

    buildah_bins = inspector.discover_binaries("buildah")
    assert "buildah" in buildah_bins


def test_rule_synthesizer_archive_rule():
    """Verify archive packages generate path traversal detection rules."""
    synthesizer = RuleSynthesizer()
    req = MitigationRequest(
        cve_id="CVE-2024-38077",
        package_name="libarchive13",
        installed_version="3.6.2",
        epss_score=0.85,
        ticket_path="/tmp/test.md",
    )
    rule = synthesizer.synthesize_rule(req, ["bsdtar", "tar"])
    assert "Oakai Mitigate CVE-2024-38077" in rule.rule
    assert rule.priority == FalcoPriority.CRITICAL
    assert "proc.name in (bsdtar, tar)" in rule.condition
    assert "proc.args contains '../'" in rule.condition

    yaml_text = synthesizer.render_yaml(rule)
    assert "Oakai Mitigate CVE-2024-38077" in yaml_text


def test_rule_synthesizer_container_rule():
    """Verify container tool packages generate host tampering detection rules."""
    synthesizer = RuleSynthesizer()
    req = MitigationRequest(
        cve_id="CVE-2024-11218",
        package_name="buildah",
        installed_version="1.28.2",
        epss_score=0.03,
        ticket_path="/tmp/test.md",
    )
    rule = synthesizer.synthesize_rule(req, ["buildah"])
    assert rule.priority == FalcoPriority.ERROR
    assert "proc.name in (buildah)" in rule.condition
    assert "/etc/shadow" in rule.condition


def test_rule_validator_accepts_valid_yaml():
    """Verify validator validates compliant Falco rule YAML documents."""
    synthesizer = RuleSynthesizer()
    validator = RuleValidator()
    req = MitigationRequest(
        cve_id="CVE-2024-38077",
        package_name="libarchive13",
        installed_version="3.6.2",
        epss_score=0.85,
        ticket_path="/tmp/test.md",
    )
    rule = synthesizer.synthesize_rule(req, ["bsdtar"])
    yaml_text = synthesizer.render_yaml(rule)

    valid, msg = validator.validate_rule_yaml(yaml_text)
    assert valid is True
    assert "Valid Falco rule syntax" in msg


def test_rule_deployer_updates_ticket():
    """Verify deployer writes rule file and injects frontmatter into ticket."""
    with tempfile.TemporaryDirectory() as temp_dir:
        rules_dir = Path(temp_dir) / "rules"
        ticket_file = Path(temp_dir) / "EXC-0001.md"

        initial_ticket_content = """---
id: EXC-0001
cve_id: CVE-2024-38077
package_name: libarchive13
status: remediation_required
---

# EXC-0001: Exception
Initial content.
"""
        ticket_file.write_text(initial_ticket_content, encoding="utf-8")

        deployer = RuleDeployer(rules_dir=str(rules_dir))
        req = MitigationRequest(
            cve_id="CVE-2024-38077",
            package_name="libarchive13",
            installed_version="3.6.2",
            epss_score=0.85,
            ticket_path=str(ticket_file),
        )

        result = deployer.deploy_rule(
            req, "Oakai Mitigate CVE-2024-38077", "- rule: test\n  desc: test\n"
        )
        assert result.deployed is True
        assert Path(result.rule_file).exists()

        # Verify frontmatter injection
        updated_ticket = ticket_file.read_text(encoding="utf-8")
        assert "compensating_control_active: true" in updated_ticket
        assert "compensating_control_ref: 'Oakai Mitigate CVE-2024-38077'" in updated_ticket
        assert "## Compensating Runtime Control Deployed" in updated_ticket


def test_uds_socket_roundtrip(mocker):
    """Verify IPC receives rejected finding, deploys rule, and forwards."""
    with tempfile.TemporaryDirectory() as temp_dir:
        mit_sock = str(Path(temp_dir) / "mitigate.sock")
        appr_sock = str(Path(temp_dir) / "approve.sock")
        rules_dir = Path(temp_dir) / "rules"
        ticket_file = Path(temp_dir) / "EXC-0001.md"
        ticket_file.write_text("---\nid: EXC-0001\n---\nBody\n", encoding="utf-8")

        server = UdsMitigationServer(
            socket_path=mit_sock,
            downstream_approve_socket=appr_sock,
            rules_dir=str(rules_dir),
        )
        server_thread = threading.Thread(target=server.start, daemon=True)
        server_thread.start()

        import time

        time.sleep(0.1)

        client_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client_sock.connect(mit_sock)

        payload = [
            {
                "cve_id": "CVE-2024-38077",
                "package_name": "libarchive13",
                "installed_version": "3.6.2",
                "epss_score": 0.85,
                "ticket_path": str(ticket_file),
            }
        ]
        client_sock.sendall(json.dumps(payload).encode("utf-8"))
        client_sock.shutdown(socket.SHUT_WR)

        response_raw = client_sock.recv(8192).decode("utf-8")
        client_sock.close()
        server.stop()

        results = json.loads(response_raw)
        assert len(results) == 1
        assert results[0]["cve_id"] == "CVE-2024-38077"
        assert results[0]["syntax_valid"] is True
        assert results[0]["deployed"] is True


def test_deployer_stages_host_falco_reload_trigger(tmp_path):
    """Verify RuleDeployer writes SHA-256 verified trigger JSON for host reconciler."""
    rules_dir = tmp_path / "rules"
    trigger_file = tmp_path / "ipc" / "falco_reload.json"
    trigger_file.parent.mkdir(parents=True, exist_ok=True)
    ticket_file = tmp_path / "EXC-0038.md"
    ticket_file.write_text("---\nid: EXC-0038\n---\nBody\n", encoding="utf-8")

    deployer = RuleDeployer(rules_dir=str(rules_dir), reload_trigger_path=str(trigger_file))
    req = MitigationRequest(
        cve_id="CVE-2026-77692",
        package_name="bind9-host",
        installed_version="1:9.18",
        epss_score=0.0656,
        ticket_path=str(ticket_file),
    )

    res = deployer.deploy_rule(
        req,
        "Oakai Mitigate CVE-2026-77692 (bind9-host)",
        "- rule: test\n  desc: test\n",
    )
    assert res.deployed is True
    assert trigger_file.exists()
    trig = json.loads(trigger_file.read_text(encoding="utf-8"))
    assert len(trig["pending_rules"]) == 1
    assert trig["pending_rules"][0]["filename"] == "oakai_mitigate_cve_2026_77692.yaml"
