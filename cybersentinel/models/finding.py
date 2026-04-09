"""Finding model — represents a single security finding."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"


@dataclass
class Finding:
    """A single security finding produced by a sub-agent.

    Findings are immutable once created. They can be marked as false positives
    but never deleted (Safety Rule 4).
    """
    title: str
    severity: Severity
    description: str
    affected_component: str
    agent_source: str  # Which sub-agent produced this finding

    # CVE / CWE references
    cve_ids: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    epss_score: Optional[float] = None
    cisa_kev: bool = False

    # MITRE ATT&CK mapping
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    mitre_mitigations: list[str] = field(default_factory=list)

    # Remediation
    remediation: str = ""
    compensating_controls: str = ""
    verification_steps: str = ""

    # Detection
    detection_guidance: str = ""
    sigma_rule: Optional[str] = None

    # Metadata
    confidence: str = "high"  # high, medium, low
    status: str = "open"  # open, confirmed, false_positive, resolved
    false_positive_reason: Optional[str] = None
    evidence: str = ""

    def to_dict(self) -> dict:
        """Serialize for session storage and reporting."""
        return {
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "affected_component": self.affected_component,
            "agent_source": self.agent_source,
            "cve_ids": self.cve_ids,
            "cwe_ids": self.cwe_ids,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "epss_score": self.epss_score,
            "cisa_kev": self.cisa_kev,
            "mitre_tactics": self.mitre_tactics,
            "mitre_techniques": self.mitre_techniques,
            "mitre_mitigations": self.mitre_mitigations,
            "remediation": self.remediation,
            "compensating_controls": self.compensating_controls,
            "verification_steps": self.verification_steps,
            "detection_guidance": self.detection_guidance,
            "sigma_rule": self.sigma_rule,
            "confidence": self.confidence,
            "status": self.status,
            "false_positive_reason": self.false_positive_reason,
            "evidence": self.evidence,
        }

    def __str__(self) -> str:
        cves = ", ".join(self.cve_ids) if self.cve_ids else "N/A"
        return (
            f"[{self.severity.value.upper()}] {self.title}\n"
            f"  Component: {self.affected_component}\n"
            f"  CVE(s): {cves}\n"
            f"  CVSS: {self.cvss_score or 'N/A'}\n"
            f"  ATT&CK: {', '.join(self.mitre_techniques) or 'N/A'}\n"
            f"  Source: {self.agent_source}"
        )
