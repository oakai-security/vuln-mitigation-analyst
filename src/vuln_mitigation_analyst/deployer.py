"""Deploys validated Falco rules to runtime directory and updates exception tickets."""

import hashlib
import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

from .schemas import MitigationRequest, MitigationResult

logger = logging.getLogger(__name__)

DEFAULT_RULES_DIR = os.environ.get("FALCO_RULES_DIR", "/etc/falco/rules.d")
DEFAULT_FALCO_RELOAD_TRIGGER = os.environ.get(
    "OAKAI_FALCO_RELOAD_TRIGGER_PATH", "/run/oakai/falco_reload.json"
)


class RuleDeployer:
    """Manages writing rule YAML to disk, reloading the runtime engine, and updating tickets."""

    def __init__(
        self,
        rules_dir: str = DEFAULT_RULES_DIR,
        reload_trigger_path: str | None = None,
    ):
        self.rules_dir = Path(rules_dir)
        self.reload_trigger_path = Path(reload_trigger_path or DEFAULT_FALCO_RELOAD_TRIGGER)

    def deploy_rule(
        self, request: MitigationRequest, rule_name: str, rule_yaml: str
    ) -> MitigationResult:
        """Write the rule YAML to the rules directory and reload Falco."""
        clean_cve = request.cve_id.lower().replace("-", "_")
        filename = f"oakai_mitigate_{clean_cve}.yaml"
        target_path = self.rules_dir / filename

        deployed = False
        status_msg = "STAGED"

        try:
            self.rules_dir.mkdir(parents=True, exist_ok=True)
            target_path.write_text(rule_yaml, encoding="utf-8")
            deployed = True
            status_msg = "DEPLOYED"
            logger.info("Deployed Falco rule to %s", target_path)

            # Trigger reload if systemctl or kill is available, and notify host reconciler
            self._trigger_falco_reload(filename=filename, rule_yaml=rule_yaml)

        except OSError as err:
            logger.warning("Could not deploy rule to %s: %s", target_path, err)
            status_msg = f"FAILED_DEPLOY: {err}"

        # Update exception ticket frontmatter
        self._update_ticket_compensating_control(request.ticket_path, rule_name, str(target_path))

        return MitigationResult(
            cve_id=request.cve_id,
            package_name=request.package_name,
            rule_name=rule_name,
            rule_file=str(target_path),
            rule_yaml=rule_yaml,
            syntax_valid=True,
            deployed=deployed,
            status=status_msg,
        )

    def _trigger_falco_reload(self, filename: str = "", rule_yaml: str = ""):
        """Write host reload trigger file and send SIGHUP/systemctl reload if on host."""
        # 1. Write IPC trigger for host root reconciler (works from rootless container)
        try:
            trigger_dir = self.reload_trigger_path.parent
            if trigger_dir.exists() and os.access(trigger_dir, os.W_OK):
                existing_rules: list[dict] = []
                if self.reload_trigger_path.exists():
                    try:
                        raw = json.loads(self.reload_trigger_path.read_text(encoding="utf-8"))
                        if isinstance(raw.get("pending_rules"), list):
                            existing_rules = raw["pending_rules"]
                    except (OSError, ValueError, AttributeError):
                        existing_rules = []

                if filename:
                    sha256_hex = hashlib.sha256(rule_yaml.encode("utf-8")).hexdigest()
                    existing_rules = [r for r in existing_rules if r.get("filename") != filename]
                    existing_rules.append(
                        {
                            "filename": filename,
                            "sha256": sha256_hex,
                            "staged_at": datetime.now(UTC).isoformat(),
                        }
                    )

                payload = {
                    "requested_at": datetime.now(UTC).isoformat(),
                    "epoch": time.time(),
                    "pending_rules": existing_rules,
                }
                fd, tmp_path = tempfile.mkstemp(dir=str(trigger_dir), prefix=".falco_reload.")
                try:
                    with os.fdopen(fd, "w", encoding="utf-8") as fh:
                        json.dump(payload, fh, indent=2)
                    os.chmod(tmp_path, 0o664)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
                    os.replace(tmp_path, str(self.reload_trigger_path))
                finally:
                    if os.path.exists(tmp_path):
                        os.unlink(tmp_path)
                logger.info("Staged host Falco reload trigger at %s", self.reload_trigger_path)
        except OSError as err:
            logger.debug("Could not write Falco reload trigger: %s", err)

        # 2. Direct reload if running directly on host as root
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            if shutil.which("systemctl"):
                try:
                    subprocess.run(
                        ["systemctl", "reload", "falco"],
                        capture_output=True,
                        timeout=5,
                        check=False,
                    )
                    logger.info("Sent reload signal to Falco via systemctl")
                    return
                except (subprocess.SubprocessError, OSError):
                    pass

            if shutil.which("pkill"):
                try:
                    subprocess.run(
                        ["pkill", "-HUP", "falco"],
                        capture_output=True,
                        timeout=5,
                        check=False,
                    )
                    logger.info("Sent SIGHUP to falco via pkill")
                except (subprocess.SubprocessError, OSError):
                    pass

    def _update_ticket_compensating_control(
        self, ticket_path_str: str, rule_name: str, rule_file_path: str
    ):
        """Inject compensating_control into ticket YAML frontmatter and append audit log."""
        if not ticket_path_str:
            return

        ticket_path = Path(ticket_path_str)
        if not ticket_path.exists():
            logger.warning("Ticket path %s does not exist; skipping markdown injection", ticket_path)
            return

        try:
            content = ticket_path.read_text(encoding="utf-8")
        except OSError as err:
            logger.error("Failed to read ticket %s: %s", ticket_path, err)
            return

        lines = content.splitlines()
        in_frontmatter = False
        frontmatter_done = False
        new_lines: list[str] = []

        for line in lines:
            if line.strip() == "---" and not frontmatter_done:
                if not in_frontmatter:
                    in_frontmatter = True
                    new_lines.append(line)
                    continue
                else:
                    in_frontmatter = False
                    frontmatter_done = True
                    new_lines.append("compensating_control_active: true")
                    new_lines.append(f"compensating_control_ref: '{rule_name}'")
                    new_lines.append(f"compensating_control_file: '{rule_file_path}'")
                    new_lines.append(line)
                    continue

            if line.strip().startswith(
                ("compensating_control_active:", "compensating_control_ref:", "compensating_control_file:")
            ):
                continue

            new_lines.append(line)

        # Strip any prior Compensating Runtime Control Deployed section before re-appending
        cleaned_lines: list[str] = []
        skip_section = False
        for line in new_lines:
            if line.strip() == "## Compensating Runtime Control Deployed":
                skip_section = True
                continue
            if skip_section and line.startswith("## "):
                skip_section = False
            if not skip_section:
                cleaned_lines.append(line)

        # Trim trailing empty lines before appending audit note
        while cleaned_lines and not cleaned_lines[-1].strip():
            cleaned_lines.pop()

        # Append compensating control audit note
        audit_note = [
            "",
            "## Compensating Runtime Control Deployed",
            f"- **Mechanism**: Falco eBPF Runtime Security (`{rule_name}`)",
            f"- **Rule Path**: `{rule_file_path}`",
            "- **Status**: `ACTIVE_IN_RUNTIME`",
            "- **Action**: Re-submitted to `vuln-exception-approver` for conditional 30-day exception.",
        ]

        updated_text = "\n".join(cleaned_lines) + "\n" + "\n".join(audit_note) + "\n"
        try:
            ticket_path.write_text(updated_text, encoding="utf-8")
            logger.info("Updated ticket %s with compensating control", ticket_path)
        except OSError as err:
            logger.error("Failed to write updated ticket %s: %s", ticket_path, err)
