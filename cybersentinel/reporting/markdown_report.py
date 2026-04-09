"""Markdown Report Generator — generates comprehensive markdown reports."""

from datetime import datetime
from typing import Optional
from collections import defaultdict


class MarkdownReportGenerator:
    """Generates comprehensive markdown security reports.

    Reports are formatted for easy integration with GitHub, wikis, and other
    markdown-based platforms. Includes mermaid diagram syntax for attack chains.
    """

    def __init__(self):
        """Initialize markdown report generator."""
        self.severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}

    def generate(
        self,
        findings: list,
        scan_metadata: dict,
        chains: Optional[list] = None,
        compliance_map: Optional[dict] = None
    ) -> str:
        """Generate complete markdown report.

        Args:
            findings: List of Finding objects or dicts
            scan_metadata: Dict with scan info
            chains: List of attack chains
            compliance_map: Compliance framework mapping

        Returns:
            Complete markdown string
        """
        # Convert findings to dicts
        findings_data = [f.to_dict() if hasattr(f, 'to_dict') else f for f in findings]

        # Build report sections
        parts = [
            self._header(scan_metadata),
            self._table_of_contents(),
            self._executive_summary(findings_data, scan_metadata),
            self._severity_summary(findings_data),
            self._methodology(),
            self._findings_section(findings_data),
        ]

        if chains:
            parts.append(self._attack_chains_section(chains))

        if compliance_map:
            parts.append(self._compliance_section(compliance_map, findings_data))

        parts.append(self._timeline_section(findings_data))
        parts.append(self._appendix(scan_metadata))

        return "\n".join(parts)

    def _header(self, metadata: dict) -> str:
        """Generate report header."""
        timestamp = metadata.get('timestamp', datetime.now().isoformat())
        target = metadata.get('target', 'Unknown')
        mode = metadata.get('mode', 'Unknown')

        return f"""# CyberSentinel Security Assessment Report

**Target:** {target}
**Assessment Date:** {timestamp}
**Assessment Mode:** {mode}
**Report Generated:** {datetime.now().isoformat()}

---

## Overview

This report contains the results of a comprehensive security assessment conducted by CyberSentinel.
The assessment identified security vulnerabilities, misconfigurations, and compliance gaps across
the target environment. Findings are categorized by severity and include detailed remediation guidance.

**⚠️ CONFIDENTIAL:** This report contains sensitive security information. Handle with appropriate
confidentiality controls and limit distribution to authorized personnel only.

---
"""

    def _table_of_contents(self) -> str:
        """Generate table of contents."""
        return """## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Severity Summary](#severity-summary)
3. [Assessment Methodology](#assessment-methodology)
4. [Detailed Findings](#detailed-findings)
5. [Attack Chains](#attack-chains)
6. [Compliance Mapping](#compliance-mapping)
7. [Timeline](#timeline)
8. [Appendix](#appendix)

---
"""

    def _executive_summary(self, findings: list, metadata: dict) -> str:
        """Generate executive summary."""
        severity_counts = self._count_by_severity(findings)
        total = len(findings)
        risk_score = self._calculate_risk_score(severity_counts)

        return f"""## Executive Summary

### Finding Statistics

| Severity | Count |
|----------|-------|
| Critical | {severity_counts.get('critical', 0)} |
| High | {severity_counts.get('high', 0)} |
| Medium | {severity_counts.get('medium', 0)} |
| Low | {severity_counts.get('low', 0)} |
| Informational | {severity_counts.get('informational', 0)} |
| **TOTAL** | **{total}** |

### Overall Risk Assessment

**Risk Score:** {risk_score}/100

The security assessment identified {total} findings across the target environment. Of these:
- **{severity_counts.get('critical', 0)} Critical** findings require immediate remediation
- **{severity_counts.get('high', 0)} High** severity findings should be prioritized for remediation
- **{severity_counts.get('medium', 0)} Medium** severity findings should be addressed in the near term
- **{severity_counts.get('low', 0)} Low** severity findings can be addressed during regular maintenance

### Recommendations

1. **Immediate Action:** Address all critical and high-severity findings within the next 7 days
2. **Short Term:** Remediate medium-severity findings within 30 days
3. **Long Term:** Schedule remediation of low-severity findings in the next quarterly review cycle
4. **Continuous:** Implement automated scanning and monitoring to prevent regression

---
"""

    def _severity_summary(self, findings: list) -> str:
        """Generate severity breakdown with status."""
        by_severity = defaultdict(list)
        for finding in findings:
            severity = finding.get('severity', 'informational')
            by_severity[severity].append(finding)

        sections = []
        for severity in ['critical', 'high', 'medium', 'low', 'informational']:
            if severity not in by_severity:
                continue

            findings_for_severity = by_severity[severity]
            icon = self._get_severity_icon(severity)

            section = f"\n### {icon} {severity.capitalize()} Severity ({len(findings_for_severity)})\n\n"
            section += "| Title | Component | CVE | CVSS | Status |\n"
            section += "|-------|-----------|-----|------|--------|\n"

            for finding in findings_for_severity:
                title = finding.get('title', 'Unknown')[:60]
                component = finding.get('affected_component', 'N/A')[:30]
                cves = ", ".join(finding.get('cve_ids', []))[:20] or "N/A"
                cvss = finding.get('cvss_score', 'N/A')
                status = finding.get('status', 'open')

                section += f"| {title} | {component} | {cves} | {cvss} | {status} |\n"

            sections.append(section)

        return f"""## Severity Summary
{"".join(sections)}

---
"""

    def _methodology(self) -> str:
        """Generate methodology section."""
        return """## Assessment Methodology

### Scope

This assessment evaluated the target environment for security vulnerabilities, misconfigurations,
and compliance gaps using automated scanning and manual analysis.

### Tools & Techniques

CyberSentinel employs multiple specialized agents to perform comprehensive security analysis:

- **Vulnerability Scanner:** Identifies known CVEs and security weaknesses
- **Configuration Auditor:** Reviews system and application configurations for security issues
- **Dependency Analyzer:** Examines software dependencies for vulnerable packages
- **Secret Detector:** Scans for exposed credentials, API keys, and sensitive data
- **Compliance Mapper:** Maps findings to industry standards and regulatory requirements

### Framework References

Findings are cross-referenced with industry-standard frameworks including:

- **NIST SP 800-53:** Security and privacy controls
- **CWE/CVSS:** Common Weakness Enumeration and Common Vulnerability Scoring System
- **MITRE ATT&CK:** Adversary tactics and techniques
- **PCI-DSS:** Payment Card Industry Data Security Standard
- **SOC2:** Service Organization Control framework

### Risk Rating

Findings are rated using:

- **CVSS v3.1:** Vector-based vulnerability severity scoring
- **EPSS:** Exploit Prediction Scoring System for exploitation likelihood
- **Temporal factors:** Considers asset criticality and business context

---
"""

    def _findings_section(self, findings: list) -> str:
        """Generate detailed findings section."""
        # Sort by severity
        sorted_findings = sorted(findings, key=lambda f: self.severity_order.get(f.get('severity', 'info'), 5))

        sections = ["\n## Detailed Findings\n"]

        for i, finding in enumerate(sorted_findings, 1):
            title = finding.get('title', 'Unknown')
            severity = finding.get('severity', 'informational').upper()
            component = finding.get('affected_component', 'N/A')
            description = finding.get('description', 'No description provided')
            cves = finding.get('cve_ids', [])
            cvss = finding.get('cvss_score', 'N/A')
            epss = finding.get('epss_score', 'N/A')
            status = finding.get('status', 'open')
            confidence = finding.get('confidence', 'high').upper()
            evidence = finding.get('evidence', 'No evidence provided')
            remediation = finding.get('remediation', 'No remediation guidance available')
            detection = finding.get('detection_guidance', 'No detection guidance available')
            techniques = finding.get('mitre_techniques', [])
            tactics = finding.get('mitre_tactics', [])

            icon = self._get_severity_icon(severity.lower())

            section = f"""
### {i}. {icon} {title}

**Severity:** {severity}
**Status:** {status.upper()}
**Confidence:** {confidence}
**Component:** {component}

#### Summary

{description}

#### Details

| Field | Value |
|-------|-------|
| CVSS Score | {cvss} |
| EPSS Score | {epss} |
| CVE(s) | {", ".join(cves) if cves else "N/A"} |
| Agent Source | {finding.get('agent_source', 'N/A')} |
| CISA KEV | {'Yes' if finding.get('cisa_kev') else 'No'} |

#### MITRE ATT&CK Mapping

"""
            if tactics or techniques:
                section += f"- **Tactics:** {', '.join(tactics) if tactics else 'N/A'}\n"
                section += f"- **Techniques:** {', '.join(techniques) if techniques else 'N/A'}\n"
            else:
                section += "- No MITRE ATT&CK mappings available\n"

            section += f"""

#### Evidence

{evidence}

#### Remediation

{remediation}

#### Detection Guidance

{detection}

"""
            sigma_rule = finding.get('sigma_rule')
            if sigma_rule:
                section += f"""
#### Detection Rule (Sigma)

```yaml
{sigma_rule}
```

"""

            sections.append(section)

        return "\n".join(sections) + "\n---\n"

    def _attack_chains_section(self, chains: list) -> str:
        """Generate attack chains section using mermaid diagrams."""
        if not chains:
            return ""

        sections = ["\n## Attack Chains\n"]

        for i, chain in enumerate(chains, 1):
            sections.append(f"\n### Attack Chain {i}\n\n")

            # Mermaid diagram
            mermaid_steps = " --> ".join([f'A{j}["<b>{step}</b>"]' for j, step in enumerate(chain)])
            sections.append(f"""```mermaid
graph LR
    {mermaid_steps}
```

""")

            # Text description
            chain_text = " → ".join(chain)
            sections.append(f"**Sequence:** {chain_text}\n")

        return "".join(sections) + "\n---\n"

    def _compliance_section(self, compliance_map: dict, findings: list) -> str:
        """Generate compliance mapping section."""
        framework_controls = defaultdict(set)

        for finding in findings:
            title = finding.get('title', '')
            if title in compliance_map:
                for framework, controls in compliance_map[title].items():
                    framework_controls[framework].update(controls)

        if not framework_controls:
            return ""

        sections = ["\n## Compliance Mapping\n"]

        for framework in sorted(framework_controls.keys()):
            sections.append(f"\n### {framework}\n\n")

            controls = sorted(framework_controls[framework])
            sections.append("| Control | Affected Findings |\n")
            sections.append("|---------|------------------|\n")

            for control in controls:
                # Count affected findings for each control
                count = sum(1 for f in findings
                           if f.get('title', '') in compliance_map and
                           framework in compliance_map.get(f.get('title', ''), {}) and
                           control in compliance_map[f.get('title', '')][framework])
                sections.append(f"| {control} | {count} |\n")

            sections.append("\n")

        return "".join(sections) + "\n---\n"

    def _timeline_section(self, findings: list) -> str:
        """Generate timeline section."""
        sections = ["\n## Timeline\n\n"]

        # Sort by severity (critical first)
        sorted_findings = sorted(findings, key=lambda f: self.severity_order.get(f.get('severity', 'info'), 5))

        sections.append("| Time | Severity | Title | Component |\n")
        sections.append("|------|----------|-------|----------|\n")

        for finding in sorted_findings:
            severity = finding.get('severity', 'info').upper()
            title = finding.get('title', 'Unknown')[:50]
            component = finding.get('affected_component', 'N/A')[:30]

            sections.append(f"| Now | {severity} | {title} | {component} |\n")

        return "".join(sections) + "\n---\n"

    def _appendix(self, metadata: dict) -> str:
        """Generate appendix section."""
        return f"""## Appendix

### Scan Details

| Field | Value |
|-------|-------|
| Target | {metadata.get('target', 'Unknown')} |
| Scan Date | {metadata.get('timestamp', 'Unknown')} |
| Assessment Mode | {metadata.get('mode', 'Unknown')} |
| Report Generated | {datetime.now().isoformat()} |
| Status | {metadata.get('status', 'Completed')} |

### Disclaimer

This report and all findings contained herein are confidential and proprietary. Unauthorized access,
use, or distribution is prohibited. The findings represent the security posture at the time of assessment
and may not reflect real-time changes.

### Document History

| Date | Version | Changes |
|------|---------|---------|
| {datetime.now().strftime('%Y-%m-%d')} | 1.0 | Initial report |

---

**CyberSentinel Security Assessment Report**
Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""

    def _count_by_severity(self, findings: list) -> dict:
        """Count findings by severity."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
        for finding in findings:
            severity = finding.get('severity', 'informational')
            if severity in counts:
                counts[severity] += 1
        return counts

    def _calculate_risk_score(self, severity_counts: dict) -> int:
        """Calculate overall risk score."""
        critical = severity_counts.get('critical', 0) * 25
        high = severity_counts.get('high', 0) * 10
        medium = severity_counts.get('medium', 0) * 3
        return min(100, critical + high + medium)

    def _get_severity_icon(self, severity: str) -> str:
        """Get emoji icon for severity level."""
        icons = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "informational": "🔵"
        }
        return icons.get(severity, "⭕")
