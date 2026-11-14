"""Pydantic schemas and models for Falco rule synthesis and vulnerability mitigation."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


def _utc_now() -> datetime:
    return datetime.now(UTC)


class FalcoPriority(StrEnum):
    """Severity priority levels supported by Falco engine."""

    EMERGENCY = "EMERGENCY"
    ALERT = "ALERT"
    CRITICAL = "CRITICAL"
    ERROR = "ERROR"
    WARNING = "WARNING"
    NOTICE = "NOTICE"
    INFORMATIONAL = "INFORMATIONAL"
    DEBUG = "DEBUG"


class FalcoRule(BaseModel):
    """Machine-parseable Falco eBPF detection rule model."""

    model_config = ConfigDict(extra="ignore")

    rule: str = Field(..., min_length=3, description="Unique human-readable rule name")
    desc: str = Field(..., description="Description of the security threat detected")
    condition: str = Field(..., description="Falco macro and syscall filter expression")
    output: str = Field(..., description="Formatted log output message with macro tokens")
    priority: FalcoPriority = Field(
        default=FalcoPriority.CRITICAL, description="Alert priority level"
    )
    tags: list[str] = Field(
        default_factory=list, description="Categorization and CVE tags"
    )


class MitigationRequest(BaseModel):
    """Input payload representing a rejected vulnerability requiring runtime mitigation."""

    model_config = ConfigDict(extra="ignore")

    cve_id: str = Field(..., description="CVE identifier (format: CVE-YYYY-NNNNN)")
    package_name: str = Field(..., min_length=1, description="Target package name")
    installed_version: str = Field(..., description="Installed package version")
    epss_score: float = Field(..., ge=0.0, le=1.0, description="FIRST.org EPSS exploit probability")
    ticket_path: str = Field(..., description="Path to the Markdown exception ticket")
    cvss_base: float = Field(default=7.5, description="Base CVSS vulnerability score")
    description: str = Field(default="", description="Vulnerability description")
    host: str = Field(default="lejeune", description="Target host node")


class MitigationResult(BaseModel):
    """Result of Falco rule synthesis, validation, and deployment."""

    model_config = ConfigDict(extra="ignore")

    cve_id: str
    package_name: str
    rule_name: str
    rule_file: str
    rule_yaml: str
    syntax_valid: bool
    deployed: bool
    status: str
    applied_at: datetime = Field(default_factory=_utc_now)
    details: dict[str, Any] = Field(default_factory=dict)
