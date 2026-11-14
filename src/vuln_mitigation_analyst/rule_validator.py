"""Validates generated Falco rules against schema and CLI syntax checkers."""

import logging
import shutil
import subprocess
import tempfile

import yaml

from .schemas import FalcoRule

logger = logging.getLogger(__name__)


class RuleValidator:
    """Verifies that generated Falco rules are syntactically sound and engine-compatible."""

    def validate_rule_yaml(self, rule_yaml: str) -> tuple[bool, str]:
        """Validate YAML structure and required Falco keys."""
        try:
            data = yaml.safe_load(rule_yaml)
            if not isinstance(data, list) or len(data) == 0:
                return False, "Falco rule document must be a non-empty list of rule objects"

            rule_obj = data[0]
            required_keys = ["rule", "desc", "condition", "output", "priority"]
            for key in required_keys:
                if key not in rule_obj:
                    return False, f"Missing required Falco rule key: {key}"

            # Verify through Pydantic
            FalcoRule(**rule_obj)

        except (yaml.YAMLError, ValueError) as err:
            logger.error("YAML validation failed: %s", err)
            return False, str(err)

        # Optional: Run falco CLI validator if installed on host
        falco_bin = shutil.which("falco")
        if falco_bin:
            try:
                with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=True) as tmp:
                    tmp.write(rule_yaml)
                    tmp.flush()
                    res = subprocess.run(
                        [falco_bin, "--validate", tmp.name],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        check=False,
                    )
                    if res.returncode != 0:
                        logger.warning("falco --validate warning: %s", res.stderr)
                        return False, f"Falco binary rejected rule: {res.stderr.strip()}"
            except (subprocess.SubprocessError, OSError) as err:
                logger.debug("Falco CLI validation skipped: %s", err)

        return True, "Valid Falco rule syntax"
