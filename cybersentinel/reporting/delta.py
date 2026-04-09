"""Delta Reporter — compares scans and generates delta reports."""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from collections import defaultdict


@dataclass
class DeltaReport:
    """Represents changes between two scan runs.

    Attributes:
        new_findings: Findings discovered in current scan only
        resolved_findings: Findings from baseline that are no longer present
        persisting_findings: Findings present in both scans
        escalated_findings: Findings with increased severity
        regression_findings: Previously resolved findings that returned
    """
    new_findings: List[Dict] = field(default_factory=list)
    resolved_findings: List[Dict] = field(default_factory=list)
    persisting_findings: List[Dict] = field(default_factory=list)
    escalated_findings: List[Tuple[Dict, Dict]] = field(default_factory=list)  # (old, new)
    regression_findings: List[Dict] = field(default_factory=list)

    def summary(self) -> Dict[str, int]:
        """Get summary counts."""
        return {
            "new": len(self.new_findings),
            "resolved": len(self.resolved_findings),
            "persisting": len(self.persisting_findings),
            "escalated": len(self.escalated_findings),
            "regression": len(self.regression_findings),
        }


class DeltaReporter:
    """Compares two scan runs and generates delta reports."""

    def __init__(self):
        """Initialize delta reporter."""
        self.severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}

    def compare(
        self,
        current_findings: List,
        baseline_findings: List
    ) -> DeltaReport:
        """Compare current scan to baseline scan.

        Matching logic: same CVE + same component = same finding

        Args:
            current_findings: List of Finding objects/dicts from current scan
            baseline_findings: List of Finding objects/dicts from baseline scan

        Returns:
            DeltaReport with categorized changes
        """
        # Convert to dicts
        current_data = [f.to_dict() if hasattr(f, 'to_dict') else f for f in current_findings]
        baseline_data = [f.to_dict() if hasattr(f, 'to_dict') else f for f in baseline_findings]

        # Build key -> finding maps for matching
        current_map = self._build_finding_map(current_data)
        baseline_map = self._build_finding_map(baseline_data)

        delta = DeltaReport()

        # Process current findings
        for key, current_finding in current_map.items():
            if key not in baseline_map:
                # New finding
                delta.new_findings.append(current_finding)
            else:
                baseline_finding = baseline_map[key]

                # Check for severity escalation
                current_sev = current_finding.get('severity', 'informational')
                baseline_sev = baseline_finding.get('severity', 'informational')

                if (self.severity_order.get(current_sev, 5) <
                    self.severity_order.get(baseline_sev, 5)):
                    # Severity increased
                    delta.escalated_findings.append((baseline_finding, current_finding))
                else:
                    # Persisting finding
                    delta.persisting_findings.append(current_finding)

        # Process baseline findings
        for key, baseline_finding in baseline_map.items():
            if key not in current_map:
                # Check if it was marked as resolved
                baseline_status = baseline_finding.get('status', 'open')
                if baseline_status == 'resolved':
                    # Check if it came back
                    delta.regression_findings.append(baseline_finding)
                else:
                    # Resolved finding
                    delta.resolved_findings.append(baseline_finding)

        return delta

    def generate_delta_summary(self, delta: DeltaReport) -> str:
        """Generate human-readable delta summary.

        Args:
            delta: DeltaReport from compare()

        Returns:
            Formatted summary string
        """
        summary = delta.summary()

        lines = [
            "# Delta Report Summary",
            "",
            "## Overview",
            f"**New Findings:** {summary['new']}",
            f"**Resolved Findings:** {summary['resolved']}",
            f"**Persisting Findings:** {summary['persisting']}",
            f"**Escalated Findings:** {summary['escalated']}",
            f"**Regressions:** {summary['regression']}",
            "",
        ]

        if summary['new'] > 0:
            lines.extend([
                "## New Findings",
                ""
            ])
            for finding in delta.new_findings:
                severity = finding.get('severity', 'info').upper()
                title = finding.get('title', 'Unknown')
                component = finding.get('affected_component', 'N/A')
                lines.append(f"- [{severity}] {title} ({component})")
            lines.append("")

        if summary['resolved'] > 0:
            lines.extend([
                "## Resolved Findings",
                ""
            ])
            for finding in delta.resolved_findings:
                title = finding.get('title', 'Unknown')
                component = finding.get('affected_component', 'N/A')
                lines.append(f"- {title} ({component})")
            lines.append("")

        if summary['persisting'] > 0:
            lines.extend([
                "## Persisting Findings",
                "",
                "These findings are still present and should be prioritized for remediation:",
                ""
            ])
            for finding in delta.persisting_findings:
                severity = finding.get('severity', 'info').upper()
                title = finding.get('title', 'Unknown')
                component = finding.get('affected_component', 'N/A')
                lines.append(f"- [{severity}] {title} ({component})")
            lines.append("")

        if summary['escalated'] > 0:
            lines.extend([
                "## Escalated Findings",
                "",
                "These findings have increased in severity and require immediate attention:",
                ""
            ])
            for old, new in delta.escalated_findings:
                title = new.get('title', 'Unknown')
                old_sev = old.get('severity', 'info').upper()
                new_sev = new.get('severity', 'info').upper()
                component = new.get('affected_component', 'N/A')
                lines.append(f"- {title} ({component}): {old_sev} → {new_sev}")
            lines.append("")

        if summary['regression'] > 0:
            lines.extend([
                "## Regressions",
                "",
                "Previously resolved findings have returned:",
                ""
            ])
            for finding in delta.regression_findings:
                severity = finding.get('severity', 'info').upper()
                title = finding.get('title', 'Unknown')
                component = finding.get('affected_component', 'N/A')
                lines.append(f"- [{severity}] {title} ({component})")
            lines.append("")

        # Recommendations
        lines.extend([
            "## Recommendations",
            ""
        ])

        if summary['new'] > 0:
            lines.append(f"1. **Investigate New Findings ({summary['new']}):** " +
                        "Review and assess the {summary['new']} new findings for risk.")

        if summary['escalated'] > 0:
            lines.append(f"2. **Address Escalations ({summary['escalated']}):** " +
                        f"{summary['escalated']} findings have increased in severity.")

        if summary['persisting'] > 0:
            lines.append(f"3. **Remediate Persistent Issues ({summary['persisting']}):** " +
                        f"{summary['persisting']} findings remain unresolved.")

        if summary['regression'] > 0:
            lines.append(f"4. **Prevent Regressions ({summary['regression']}):** " +
                        f"{summary['regression']} previously resolved issues have returned.")

        if summary['resolved'] > 0:
            lines.append(f"5. **Maintain Progress:** {summary['resolved']} findings have been successfully resolved.")

        return "\n".join(lines)

    def _build_finding_map(self, findings: List[Dict]) -> Dict[Tuple, Dict]:
        """Build a map of findings keyed by (component, CVE, CWE).

        This enables matching findings across scans.

        Args:
            findings: List of finding dicts

        Returns:
            Dict mapping (component, cve_string, cwe_string) to finding
        """
        finding_map = {}

        for finding in findings:
            component = finding.get('affected_component', 'unknown')
            cves = tuple(sorted(finding.get('cve_ids', [])))
            cwes = tuple(sorted(finding.get('cwe_ids', [])))

            # Create a unique key for matching
            key = (component, cves, cwes)

            # If multiple findings with same key, use the one with highest severity
            if key in finding_map:
                existing_sev = self.severity_order.get(
                    finding_map[key].get('severity', 'info'), 5
                )
                new_sev = self.severity_order.get(finding.get('severity', 'info'), 5)
                if new_sev < existing_sev:
                    finding_map[key] = finding
            else:
                finding_map[key] = finding

        return finding_map
