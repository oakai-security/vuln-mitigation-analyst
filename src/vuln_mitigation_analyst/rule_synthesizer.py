"""Synthesizes scoped Falco eBPF runtime detection rules for vulnerable components."""

import json
import logging
import os
import urllib.error
import urllib.request

import yaml

from .schemas import FalcoPriority, FalcoRule, MitigationRequest

logger = logging.getLogger(__name__)

DEFAULT_OLLAMA_URL = os.environ.get(
    "OLLAMA_URL", os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
)
DEFAULT_OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:3b")

FALCO_DESC_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "desc": {
            "type": "string",
        },
    },
    "required": ["desc"],
}


class RuleSynthesizer:
    """Generates scoped Falco rules that act as compensating controls for vulnerabilities."""

    def __init__(
        self,
        ollama_url: str = DEFAULT_OLLAMA_URL,
        model: str = DEFAULT_OLLAMA_MODEL,
        use_llm: bool | None = None,
    ):
        self.ollama_url = ollama_url.rstrip("/")
        self.model = model
        if use_llm is None:
            self.use_llm = os.environ.get("OAKAI_MITIGATE_USE_LLM", "true").lower() in (
                "1",
                "true",
                "yes",
            )
        else:
            self.use_llm = use_llm

    def _query_llm_description(
        self, request: MitigationRequest, candidate_binaries: list[str]
    ) -> str | None:
        """Query local Ollama to generate a tailored Falco rule description for the CVE."""
        if not self.use_llm:
            return None

        prompt = (
            "Return ONLY a JSON object with a single key \"desc\" containing a concise 1-sentence "
            f"Falco runtime security rule description for {request.cve_id} affecting package "
            f"{request.package_name} (version {request.installed_version}, binaries: {', '.join(candidate_binaries)}). "
            f"Context: {request.description or 'Linux package vulnerability'}."
        )
        payload = json.dumps(
            {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "format": FALCO_DESC_JSON_SCHEMA,
                "options": {"temperature": 0.0, "num_ctx": 2048},
            }
        ).encode("utf-8")

        req = urllib.request.Request(
            f"{self.ollama_url}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:  # nosec B310
                body = json.loads(resp.read().decode("utf-8"))
                parsed = json.loads(body.get("response", "{}"))
                llm_desc = str(parsed.get("desc", "")).strip()
                if llm_desc and len(llm_desc) > 15:
                    logger.info(
                        "LLM (%s) synthesized Falco rule description for %s",
                        self.model,
                        request.cve_id,
                    )
                    return (
                        f"Compensating runtime control for {request.cve_id} in {request.package_name} "
                        f"(EPSS: {request.epss_score:.4f}). {llm_desc}"
                    )
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as err:
            logger.debug("LLM rule description fallback for %s: %s", request.cve_id, err)
        return None

    def synthesize_rule(
        self, request: MitigationRequest, candidate_binaries: list[str]
    ) -> FalcoRule:
        """Construct a scoped Falco rule based on package type and attack surface."""
        rule_name = f"Oakai Mitigate {request.cve_id} ({request.package_name})"
        default_desc = (
            f"Compensating runtime control for {request.cve_id} in {request.package_name}. "
            f"EPSS score: {request.epss_score:.4f}. Detects anomalous execution, path traversal, "
            "or unauthorized shell spawning."
        )
        desc = self._query_llm_description(request, candidate_binaries) or default_desc

        bin_list_str = ", ".join(candidate_binaries) if candidate_binaries else request.package_name

        # Differentiate rule conditions based on package characteristics
        pkg_lower = request.package_name.lower()

        if any(term in pkg_lower for term in ["tar", "archive", "zip", "compress"]):
            # Archive extraction vulnerability pattern: path traversal or web daemon execution
            condition = (
                f"(spawned_process and proc.name in ({bin_list_str}) and "
                "(proc.args contains '../' or proc.pname in (nginx, apache2, lighttpd, caddy, python3)))"
            )
            output = (
                f"Anomalous archive execution detected under {request.cve_id} "
                "(proc=%proc.name cmd=%proc.cmdline user=%user.name parent=%proc.pname file=%fd.name)"
            )
        elif any(term in pkg_lower for term in ["buildah", "crun", "runc", "podman", "container"]):
            # Container runtime escape pattern: unexpected root mount or sensitive host access
            condition = (
                f"(spawned_process and proc.name in ({bin_list_str}) and "
                "(proc.args contains '/etc/shadow' or proc.args contains '/root/.ssh' or proc.args contains '/proc/sys'))"
            )
            output = (
                f"Container tool host tampering detected under {request.cve_id} "
                "(proc=%proc.name cmd=%proc.cmdline user=%user.name file=%fd.name)"
            )
        elif pkg_lower in ("bind9-host", "bind9-libs", "dnsutils", "bind9-dnsutils"):
            # DNS client utility & resolver library pattern: detect unexpected execution or shell child
            condition = (
                f"(spawned_process and (proc.name in ({bin_list_str}) or "
                f"(proc.pname in ({bin_list_str}) and proc.name in (sh, bash, dash, zsh, ksh, ash))))"
            )
            output = (
                f"DNS utility or library execution detected under {request.cve_id} "
                "(proc=%proc.name parent=%proc.pname cmd=%proc.cmdline user=%user.name)"
            )
        elif any(term in pkg_lower for term in ["ssh", "bind", "daemon", "server"]):
            # Network service vulnerability pattern: shell spawning from non-interactive daemon
            condition = (
                f"(spawned_process and proc.pname in ({bin_list_str}) and "
                "proc.name in (sh, bash, dash, zsh, ksh, ash))"
            )
            output = (
                f"Suspicious shell spawned from network service under {request.cve_id} "
                "(service=%proc.pname shell=%proc.name cmd=%proc.cmdline user=%user.name)"
            )
        else:
            # General fallback: detect unexpected privileged execution or interactive shell spawning
            condition = (
                f"(spawned_process and proc.name in ({bin_list_str}) and "
                "(user.uid = 0 or proc.args contains 'chmod' or proc.args contains 'chown'))"
            )
            output = (
                f"High-risk component privileged execution under {request.cve_id} "
                "(proc=%proc.name cmd=%proc.cmdline uid=%user.uid user=%user.name)"
            )

        tags = [
            "oakai_compensating_control",
            request.cve_id,
            request.package_name,
            "security_governance",
        ]

        return FalcoRule(
            rule=rule_name,
            desc=desc,
            condition=condition,
            output=output,
            priority=FalcoPriority.CRITICAL if request.epss_score >= 0.5 else FalcoPriority.ERROR,
            tags=tags,
        )

    def render_yaml(self, rule: FalcoRule) -> str:
        """Render FalcoRule model to valid Falco rules YAML document format."""
        doc = [
            {
                "rule": rule.rule,
                "desc": rule.desc,
                "condition": rule.condition,
                "output": rule.output,
                "priority": rule.priority.value,
                "tags": rule.tags,
            }
        ]
        header = "# Automatically generated by Oakai Security vuln-mitigation-analyst\n# Compensating Runtime Control\n\n"
        return header + yaml.dump(doc, sort_keys=False, default_flow_style=False)
