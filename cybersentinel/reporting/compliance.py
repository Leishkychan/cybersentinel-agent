"""Compliance Mapper — maps findings to compliance frameworks."""

from typing import Optional, Dict, List, Set
from collections import defaultdict


class ComplianceMapper:
    """Maps security findings to compliance frameworks.

    Supports NIST 800-53, SOC2, and PCI-DSS with CWE-based mapping logic.
    """

    def __init__(self):
        """Initialize compliance mapper with framework mappings."""
        self.cwe_to_nist = self._init_cwe_to_nist()
        self.cwe_to_soc2 = self._init_cwe_to_soc2()
        self.cwe_to_pci = self._init_cwe_to_pci()

    def map_finding(self, finding) -> Dict[str, List[str]]:
        """Map a single finding to compliance controls.

        Args:
            finding: Finding object or dict

        Returns:
            Dict mapping framework name to list of applicable controls
        """
        # Convert to dict if necessary
        finding_dict = finding.to_dict() if hasattr(finding, 'to_dict') else finding

        result = {}

        # Map using CWE IDs
        cwe_ids = finding_dict.get('cwe_ids', [])
        for cwe_id in cwe_ids:
            nist_controls = self.cwe_to_nist.get(cwe_id, [])
            if nist_controls:
                result.setdefault('NIST 800-53', []).extend(nist_controls)

            soc2_controls = self.cwe_to_soc2.get(cwe_id, [])
            if soc2_controls:
                result.setdefault('SOC2', []).extend(soc2_controls)

            pci_controls = self.cwe_to_pci.get(cwe_id, [])
            if pci_controls:
                result.setdefault('PCI-DSS v4.0', []).extend(pci_controls)

        # Deduplicate within each framework
        for framework in result:
            result[framework] = sorted(list(set(result[framework])))

        return result

    def generate_compliance_report(self, findings: List, framework: str) -> str:
        """Generate compliance-specific report for a framework.

        Args:
            findings: List of Finding objects or dicts
            framework: Framework name ('NIST 800-53', 'SOC2', 'PCI-DSS v4.0')

        Returns:
            Formatted compliance report as string
        """
        # Convert findings to dicts
        findings_data = [f.to_dict() if hasattr(f, 'to_dict') else f for f in findings]

        # Collect all controls for this framework
        framework_controls = defaultdict(set)
        control_findings = defaultdict(list)

        for finding in findings_data:
            mapped = self.map_finding(finding)
            if framework in mapped:
                for control in mapped[framework]:
                    framework_controls[framework].add(control)
                    control_findings[control].append(finding.get('title', 'Unknown'))

        report_lines = [
            f"# {framework} Compliance Mapping Report",
            "",
            f"## Summary",
            f"Total Controls Referenced: {len(framework_controls[framework])}",
            f"Total Findings: {len(findings_data)}",
            "",
            f"## Control Mapping",
            "",
            "| Control | Affected Findings | Severity |",
            "|---------|------------------|----------|",
        ]

        # Build control table
        for control in sorted(framework_controls[framework]):
            finding_list = control_findings[control]
            finding_count = len(finding_list)

            # Get max severity of affected findings
            max_severity = self._get_max_severity(findings_data, finding_list)

            report_lines.append(
                f"| {control} | {finding_count} | {max_severity.upper()} |"
            )

        report_lines.extend([
            "",
            "## Control Details",
            ""
        ])

        # Control details
        for control in sorted(framework_controls[framework]):
            finding_list = control_findings[control]
            report_lines.extend([
                f"### {control}",
                "",
                "**Affected Findings:**",
                ""
            ])

            for finding_title in sorted(finding_list):
                report_lines.append(f"- {finding_title}")

            report_lines.append("")

        return "\n".join(report_lines)

    def _get_max_severity(self, findings: List[Dict], finding_titles: List[str]) -> str:
        """Get maximum severity from a list of finding titles."""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
        max_sev = "informational"
        max_order = 4

        for finding in findings:
            if finding.get('title', '') in finding_titles:
                sev = finding.get('severity', 'informational')
                order = severity_order.get(sev, 4)
                if order < max_order:
                    max_sev = sev
                    max_order = order

        return max_sev

    def _init_cwe_to_nist(self) -> Dict[str, List[str]]:
        """Initialize CWE to NIST 800-53 mapping.

        Returns comprehensive mapping of CWEs to NIST controls.
        """
        return {
            # Authentication & Authorization
            "CWE-287": ["AC-2", "AC-3", "AC-4", "IA-2", "IA-4"],
            "CWE-284": ["AC-2", "AC-3", "AC-5", "AC-6"],
            "CWE-269": ["AC-6", "AC-5", "AC-3"],
            "CWE-276": ["AC-2", "AC-3", "AC-5", "AC-6"],
            "CWE-275": ["AC-3", "AC-6", "AC-5"],

            # Injection
            "CWE-89": ["SI-10", "SI-4", "AC-4"],
            "CWE-90": ["SI-10", "SI-4", "AC-4"],
            "CWE-91": ["SI-10", "SI-4", "AC-4"],
            "CWE-88": ["SI-10", "SI-4", "AC-4"],
            "CWE-95": ["SI-10", "SI-4", "AC-4"],
            "CWE-78": ["SI-10", "SI-4", "AC-4"],
            "CWE-94": ["SI-10", "SI-4", "AC-4"],

            # Cryptography
            "CWE-327": ["SC-12", "SC-13", "SC-28"],
            "CWE-326": ["SC-12", "SC-13"],
            "CWE-325": ["SC-12", "SC-13"],
            "CWE-330": ["SC-12", "CA-7"],
            "CWE-338": ["SC-12", "SC-28"],

            # Configuration
            "CWE-16": ["CA-2", "CA-7", "CM-3", "CM-5", "CM-6"],
            "CWE-15": ["CA-2", "CA-7", "CM-6"],
            "CWE-17": ["CA-2", "CM-6"],

            # Credential Management
            "CWE-798": ["IA-4", "IA-5", "IA-6", "IA-7"],
            "CWE-259": ["IA-5", "IA-6", "IA-7"],
            "CWE-321": ["IA-4", "IA-5", "IA-7"],
            "CWE-522": ["IA-5", "IA-7", "SC-13"],

            # Vulnerability Management
            "CWE-494": ["CA-2", "CA-7", "SI-2", "SI-4"],
            "CWE-502": ["SI-10", "SI-4"],
            "CWE-434": ["SI-10", "CM-3", "SC-7"],

            # Data Protection
            "CWE-200": ["AC-3", "AC-4", "AC-6", "AU-2", "AU-4", "SC-7"],
            "CWE-201": ["AC-3", "AC-6", "AU-2"],
            "CWE-202": ["AC-3", "AU-2"],
            "CWE-203": ["AC-3", "AC-6"],
            "CWE-209": ["AU-2", "AU-4"],

            # Monitoring & Logging
            "CWE-778": ["AU-2", "AU-4", "SI-4"],
            "CWE-532": ["AU-2", "AU-4", "AC-4"],

            # Resource Management
            "CWE-399": ["RA-5", "SI-5", "SC-5"],
            "CWE-674": ["RA-5", "SI-5"],
            "CWE-770": ["RA-5", "SI-5", "SC-5"],
            "CWE-400": ["SI-4", "SC-5"],

            # Race Conditions
            "CWE-362": ["SI-11", "SC-4"],
            "CWE-366": ["SI-11", "SC-4"],
            "CWE-367": ["SI-11"],

            # Design Flaws
            "CWE-434": ["SI-10", "CM-3"],
            "CWE-436": ["CM-5", "CM-3"],
            "CWE-437": ["CM-5"],

            # Error Handling
            "CWE-391": ["SI-4", "AU-4"],
            "CWE-392": ["SI-4", "AU-4"],
            "CWE-393": ["SI-4"],

            # Buffer Issues
            "CWE-120": ["SI-10", "SI-16"],
            "CWE-119": ["SI-10", "SI-16"],
            "CWE-121": ["SI-10", "SI-16"],
            "CWE-122": ["SI-10", "SI-16"],
            "CWE-126": ["SI-10", "SI-16"],
            "CWE-127": ["SI-10", "SI-16"],

            # XXE
            "CWE-611": ["SI-10", "SI-4"],

            # Insecure Transport
            "CWE-295": ["SC-7", "SC-13"],
            "CWE-297": ["SC-7", "SC-13"],
            "CWE-299": ["SC-7", "SC-13"],

            # SSRF
            "CWE-918": ["SI-10", "SI-4", "AC-4"],

            # Deserialization
            "CWE-502": ["SI-10", "SI-4"],
            "CWE-91": ["SI-10", "SI-4"],
        }

    def _init_cwe_to_soc2(self) -> Dict[str, List[str]]:
        """Initialize CWE to SOC2 Trust Service Criteria mapping."""
        return {
            # Security Control
            "CWE-287": ["CC6.1", "CC6.2", "CC7.2"],
            "CWE-284": ["CC6.1", "CC6.2"],
            "CWE-269": ["CC6.2"],
            "CWE-276": ["CC6.1", "CC6.2"],

            # Availability
            "CWE-399": ["A1.1", "A1.2"],
            "CWE-770": ["A1.1", "A1.2"],
            "CWE-674": ["A1.1"],

            # Confidentiality
            "CWE-200": ["C1.1", "C1.2", "CC6.1"],
            "CWE-798": ["C1.2", "CC7.2"],
            "CWE-327": ["C1.2", "CC6.2"],

            # Integrity
            "CWE-89": ["C1.2", "CC7.2"],
            "CWE-78": ["C1.2", "CC7.2"],
            "CWE-502": ["C1.2", "CC7.2"],
            "CWE-611": ["C1.2", "CC7.2"],

            # Processing Integrity
            "CWE-391": ["C1.3", "CC7.2"],
            "CWE-362": ["C1.3"],

            # Change Management
            "CWE-16": ["CC7.2", "CC9.2"],
            "CWE-434": ["CC9.2"],
            "CWE-436": ["CC9.2"],

            # Monitoring
            "CWE-778": ["CC7.3"],
            "CWE-532": ["CC7.3"],

            # Encryption
            "CWE-295": ["CC6.1", "CC6.2"],
            "CWE-326": ["CC6.2"],
            "CWE-330": ["CC6.2"],

            # Access Control
            "CWE-918": ["CC6.1", "CC7.2"],
            "CWE-275": ["CC6.1"],
        }

    def _init_cwe_to_pci(self) -> Dict[str, List[str]]:
        """Initialize CWE to PCI-DSS v4.0 requirement mapping."""
        return {
            # Requirement 1: Firewall rules, network segmentation
            "CWE-918": ["1.1", "1.2", "1.3"],
            "CWE-327": ["1.4"],

            # Requirement 2: Default security parameters
            "CWE-16": ["2.1", "2.2", "2.3", "2.4"],
            "CWE-15": ["2.1", "2.4"],

            # Requirement 3: Protect stored cardholder data
            "CWE-327": ["3.2", "3.3"],
            "CWE-330": ["3.3"],
            "CWE-200": ["3.1", "3.2"],

            # Requirement 4: Protect transmission
            "CWE-295": ["4.1", "4.2"],
            "CWE-297": ["4.1"],
            "CWE-299": ["4.1"],
            "CWE-326": ["4.2"],

            # Requirement 5: Malware prevention
            "CWE-494": ["5.1", "5.2"],
            "CWE-434": ["5.1"],

            # Requirement 6: Secure development
            "CWE-89": ["6.1", "6.2", "6.3"],
            "CWE-78": ["6.1", "6.2"],
            "CWE-502": ["6.1", "6.2"],
            "CWE-91": ["6.1", "6.2"],
            "CWE-611": ["6.1", "6.2"],
            "CWE-88": ["6.1", "6.2"],
            "CWE-94": ["6.1", "6.2"],
            "CWE-95": ["6.1", "6.2"],
            "CWE-120": ["6.2", "6.3"],
            "CWE-787": ["6.2", "6.3"],

            # Requirement 7: Access control
            "CWE-287": ["7.1", "7.2"],
            "CWE-284": ["7.1"],
            "CWE-269": ["7.1"],

            # Requirement 8: User identification/authentication
            "CWE-798": ["8.3", "8.4"],
            "CWE-259": ["8.4"],
            "CWE-321": ["8.4"],
            "CWE-522": ["8.4"],

            # Requirement 9: Physical access control
            "CWE-200": ["9.1", "9.2"],

            # Requirement 10: Logging/monitoring
            "CWE-778": ["10.3", "10.4"],
            "CWE-532": ["10.3"],
            "CWE-209": ["10.2"],

            # Requirement 11: Security testing
            "CWE-494": ["11.3", "11.4"],

            # Requirement 12: Information security policy
            "CWE-16": ["12.3", "12.4"],
        }
