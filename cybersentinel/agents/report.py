"""Report Agent — formats output and assigns final severity.

Scope: Synthesis and formatting only. Does not generate new findings,
       modify existing findings, or take any action.
"""

from __future__ import annotations

from cybersentinel.agents.base import BaseAgent
from cybersentinel.models.finding import Finding, Severity


class ReportAgent(BaseAgent):
    """Synthesizes findings into audience-appropriate reports.

    Adapts output format based on audience:
    - Security professionals: Full technical depth
    - IT operations: Actionable remediation steps
    - Executives: Business risk, cost, timeline
    - Compliance/auditors: Framework mapping, evidence

    Does NOT:
    - Generate new findings
    - Modify severity of existing findings
    - Delete or suppress findings (Rule 4)
    - Take any action beyond formatting

    Input: Aggregated findings, audience type, format preference
    Output: Formatted report
    """

    name = "report"
    description = "Report generation and formatting"

    def analyze(self, target: str, context: dict) -> list[Finding]:
        """The report agent doesn't produce findings — it formats them.

        This method exists for interface compliance. The actual report
        generation happens in the orchestrator's generate_report() method,
        which can call format_report() below.
        """
        self.validate(target, f"Report generation for {target}")
        self.log(f"Report agent invoked for {target}")
        return []

    def format_report(
        self,
        findings: list[Finding],
        audience: str = "technical",
        format: str = "markdown",
    ) -> str:
        """Format findings into a report for the specified audience.

        Args:
            findings: List of all findings to include
            audience: One of 'technical', 'executive', 'compliance', 'operations'
            format: Output format ('markdown', 'json')

        Returns:
            Formatted report string
        """
        self.log(f"Formatting report: audience={audience}, format={format}")

        if audience == "executive":
            return self._executive_report(findings)
        elif audience == "compliance":
            return self._compliance_report(findings)
        elif audience == "operations":
            return self._operations_report(findings)
        else:
            return self._technical_report(findings)

    def _technical_report(self, findings: list[Finding]) -> str:
        """Full technical depth for security professionals."""
        lines = ["# Security Assessment — Technical Report\n"]
        for i, f in enumerate(findings, 1):
            lines.append(f"## {i}. [{f.severity.value.upper()}] {f.title}")
            lines.append(f"\n**Component:** {f.affected_component}")
            lines.append(f"**CVE(s):** {', '.join(f.cve_ids) or 'N/A'}")
            lines.append(f"**CVSS:** {f.cvss_score or 'N/A'} ({f.cvss_vector or 'N/A'})")
            lines.append(f"**ATT&CK:** {', '.join(f.mitre_techniques) or 'N/A'}")
            lines.append(f"\n{f.description}")
            lines.append(f"\n**Remediation:** {f.remediation}")
            lines.append(f"\n**Detection:** {f.detection_guidance}")
            lines.append(f"\n**Verification:** {f.verification_steps}")
            lines.append("\n---\n")
        return "\n".join(lines)

    def _executive_report(self, findings: list[Finding]) -> str:
        """Business risk language for executives."""
        critical = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in findings if f.severity == Severity.HIGH)
        lines = [
            "# Security Assessment — Executive Summary\n",
            f"**Total Findings:** {len(findings)}",
            f"**Requiring Immediate Action:** {critical + high}",
            f"**Critical:** {critical} | **High:** {high}\n",
            "## Key Risks\n",
        ]
        for f in findings:
            if f.severity in (Severity.CRITICAL, Severity.HIGH):
                lines.append(f"- **{f.title}** — {f.description[:200]}")
        lines.append("\n## Recommended Actions\n")
        for f in findings:
            if f.severity in (Severity.CRITICAL, Severity.HIGH):
                lines.append(f"- {f.remediation[:200]}")
        return "\n".join(lines)

    def _compliance_report(self, findings: list[Finding]) -> str:
        """Framework-mapped report for auditors."""
        lines = ["# Security Assessment — Compliance Report\n"]
        for f in findings:
            lines.append(f"## {f.title}")
            lines.append(f"- **Severity:** {f.severity.value.upper()}")
            lines.append(f"- **CWE:** {', '.join(f.cwe_ids) or 'N/A'}")
            lines.append(f"- **CVE:** {', '.join(f.cve_ids) or 'N/A'}")
            lines.append(f"- **Remediation:** {f.remediation}")
            lines.append(f"- **Evidence:** {f.evidence}")
            lines.append("")
        return "\n".join(lines)

    def _operations_report(self, findings: list[Finding]) -> str:
        """Actionable steps for sysadmins."""
        lines = ["# Security Assessment — Operations Remediation Plan\n"]
        for i, f in enumerate(findings, 1):
            lines.append(f"## {i}. {f.title} [{f.severity.value.upper()}]")
            lines.append(f"\n**What to do:** {f.remediation}")
            lines.append(f"\n**How to verify:** {f.verification_steps}")
            lines.append(f"\n**Compensating control:** {f.compensating_controls}")
            lines.append("\n---\n")
        return "\n".join(lines)
