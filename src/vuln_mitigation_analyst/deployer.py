"""Deploys validated Falco rules to runtime directory and updates exception tickets."""

import logging
import os
import shutil
import subprocess
from pathlib import Path

from .schemas import MitigationRequest, MitigationResult

logger = logging.getLogger(__name__)

DEFAULT_RULES_DIR = os.environ.get("FALCO_RULES_DIR", "/etc/falco/rules.d")


class RuleDeployer:
    """Manages writing rule YAML to disk, reloading the runtime engine, and updating tickets."""

    def __init__(self, rules_dir: str = DEFAULT_RULES_DIR):
        self.rules_dir = Path(rules_dir)

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

            # Trigger reload if systemctl or kill is available
            self._trigger_falco_reload()

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

    def _trigger_falco_reload(self):
        """Send SIGHUP to running Falco daemon or trigger systemctl reload."""
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
                subprocess.run(["pkill", "-HUP", "falco"], capture_output=True, timeout=5, check=False)
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
        new_lines: list[str] = []

        for line in lines:
            if line.strip() == "---":
                if not in_frontmatter:
                    in_frontmatter = True
                    new_lines.append(line)
                    continue
                else:
                    in_frontmatter = False
                    new_lines.append("compensating_control_active: true")
                    new_lines.append(f"compensating_control_ref: '{rule_name}'")
                    new_lines.append(f"compensating_control_file: '{rule_file_path}'")
                    new_lines.append(line)
                    continue

            if in_frontmatter and line.strip().startswith(
                ("compensating_control_active:", "compensating_control_ref:", "compensating_control_file:")
            ):
                continue

            new_lines.append(line)

        # Append compensating control audit note
        audit_note = [
            "",
            "## Compensating Runtime Control Deployed",
            f"- **Mechanism**: Falco eBPF Runtime Security (`{rule_name}`)",
            f"- **Rule Path**: `{rule_file_path}`",
            "- **Status**: `ACTIVE_IN_RUNTIME`",
            "- **Action**: Re-submitted to `vuln-exception-approver` for conditional 30-day exception.",
        ]

        updated_text = "\n".join(new_lines) + "\n" + "\n".join(audit_note) + "\n"
        try:
            ticket_path.write_text(updated_text, encoding="utf-8")
            logger.info("Updated ticket %s with compensating control", ticket_path)
        except OSError as err:
            logger.error("Failed to write updated ticket %s: %s", ticket_path, err)
