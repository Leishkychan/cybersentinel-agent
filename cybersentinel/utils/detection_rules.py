"""Detection rule generators for Sigma and YARA formats."""

from __future__ import annotations

import re
from typing import Optional
from datetime import datetime

from cybersentinel.models.finding import Finding, Severity


# ATT&CK Technique ID to Tactic mapping
ATTACK_TECHNIQUE_TACTICS = {
    "T1190": "initial_access",      # Exploit Public-Facing Application
    "T1200": "initial_access",      # Hardware Additions
    "T1566": "initial_access",      # Phishing
    "T1091": "initial_access",      # Replication Through Removable Media
    "T1195": "initial_access",      # Supply Chain Compromise
    "T1199": "initial_access",      # Trusted Relationship
    "T1566": "initial_access",      # Phishing
    "T1528": "credential_access",   # Steal Application Access Token
    "T1110": "credential_access",   # Brute Force
    "T1555": "credential_access",   # Credentials from Password Stores
    "T1187": "credential_access",   # Forced Authentication
    "T1056": "collection",          # Input Capture
    "T1123": "collection",          # Audio Capture
    "T1119": "collection",          # Automated Exfiltration
    "T1040": "discovery",           # Network Sniffing
    "T1087": "discovery",           # Account Discovery
    "T1010": "discovery",           # Application Window Discovery
    "T1217": "discovery",           # Browser Bookmark Discovery
    "T1580": "discovery",           # Cloud Infrastructure Discovery
    "T1538": "exfiltration",        # Cloud Service Dashboard
    "T1020": "exfiltration",        # Automated Exfiltration
    "T1030": "exfiltration",        # Data Transfer Size Limits
    "T1041": "exfiltration",        # Exfiltration Over C2 Channel
    "T1011": "exfiltration",        # Exfiltration Over Other Network Medium
    "T1048": "exfiltration",        # Exfiltration Over Alternative Protocol
    "T1567": "exfiltration",        # Exfiltration Over Web Service
    "T1005": "collection",          # Data from Local System
    "T1039": "collection",          # Data from Network Shared Drive
    "T1025": "collection",          # Data from Removable Media
    "T1005": "collection",          # Data Staged
    "T1114": "collection",          # Email Collection
    "T1056": "collection",          # Input Capture
    "T1113": "collection",          # Screen Capture
    "T1115": "collection",          # Clipboard Data
    "T1530": "collection",          # Data from Cloud Storage
    "T1213": "collection",          # Data from Information Repositories
    "T1005": "collection",          # Data from Local System
    "T1074": "collection",          # Data Staged
    "T1140": "defense_evasion",     # Deobfuscate/Decode Files or Information
    "T1197": "defense_evasion",     # BITS Jobs
    "T1612": "defense_evasion",     # Build Image on Host
    "T1027": "defense_evasion",     # Obfuscated Files or Information
    "T1014": "defense_evasion",     # Rootkit
    "T1036": "defense_evasion",     # Masquerading
    "T1556": "defense_evasion",     # Modify Authentication Process
    "T1578": "defense_evasion",     # Modify Cloud Compute Infrastructure
    "T1112": "defense_evasion",     # Modify Registry
    "T1601": "defense_evasion",     # Modify System Image
    "T1599": "defense_evasion",     # Network Boundary Bridging
    "T1599": "defense_evasion",     # Network Device CLI
    "T1207": "defense_evasion",     # Rogue Domain Controller
    "T1014": "defense_evasion",     # Rootkit
    "T1480": "defense_evasion",     # Execution Guardrails
    "T1518": "discovery",           # Software Discovery
    "T1082": "discovery",           # System Information Discovery
    "T1614": "discovery",           # System Location Discovery
    "T1018": "discovery",           # Remote System Discovery
    "T1518": "discovery",           # Software Discovery
    "T1526": "discovery",           # Cloud Service Discovery
    "T1007": "discovery",           # System Service Discovery
    "T1049": "discovery",           # System Network Connections Discovery
    "T1033": "discovery",           # System Owner/User Discovery
    "T1007": "discovery",           # System Service Discovery
    "T1529": "impact",              # Service Stop
    "T1561": "impact",              # Disk Wipe
    "T1499": "impact",              # Endpoint Denial of Service
    "T1561": "impact",              # Disk Wipe
    "T1561": "impact",              # Disk Wipe
    "T1485": "impact",              # Data Destruction
    "T1490": "impact",              # Inhibit System Recovery
    "T1561": "impact",              # Disk Wipe
    "T1561": "impact",              # Disk Wipe
    "T1491": "impact",              # Defacement
    "T1561": "impact",              # Disk Wipe
    "T1531": "impact",              # Account Access Removal
    "T1490": "impact",              # Inhibit System Recovery
}

# CWE to Logsource type mapping
CWE_TO_LOGSOURCE = {
    "CWE-79": "web",               # Cross-site Scripting
    "CWE-89": "web",               # SQL Injection
    "CWE-90": "web",               # LDAP Injection
    "CWE-94": "process",           # Code Injection
    "CWE-95": "process",           # Improper Neutralization of Directives in Dynamically Evaluated Code
    "CWE-98": "process",           # Improper Control of Filename for Include/Require Statement
    "CWE-434": "web",              # Unrestricted Upload of File with Dangerous Type
    "CWE-611": "web",              # Improper Restriction of XML External Entity Reference
    "CWE-639": "auth",             # Authorization Bypass Through User-Controlled Key
    "CWE-640": "auth",             # Weak Password Recovery Mechanism
    "CWE-287": "auth",             # Improper Authentication
    "CWE-862": "auth",             # Missing Authorization
    "CWE-863": "auth",             # Incorrect Authorization
    "CWE-22": "file",              # Improper Limitation of a Pathname to a Restricted Directory
    "CWE-426": "process",          # Untrusted Search Path
    "CWE-427": "process",          # Uncontrolled Search Path Element
    "CWE-94": "process",           # Code Injection
    "CWE-427": "process",          # Uncontrolled Search Path Element
    "CWE-269": "auth",             # Improper Access Control
    "CWE-200": "process",          # Exposure of Sensitive Information to an Unauthorized Actor
    "CWE-798": "auth",             # Use of Hard-coded Credentials
    "CWE-327": "process",          # Use of a Broken or Risky Cryptographic Algorithm
    "CWE-295": "network",          # Improper Certificate Validation
    "CWE-297": "network",          # Improper Validation of Certificate with Host Mismatch
    "CWE-311": "network",          # Missing Encryption of Sensitive Data
    "CWE-312": "network",          # Cleartext Storage of Sensitive Information
    "CWE-319": "network",          # Cleartext Transmission of Sensitive Information
    "CWE-835": "process",          # Infinite Loop
    "CWE-190": "process",          # Integer Overflow or Wraparound
    "CWE-680": "process",          # Integer Overflow to Buffer Overflow
}

# Severity to Sigma level mapping
SEVERITY_TO_SIGMA_LEVEL = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
    Severity.INFO: "informational",
}


class SigmaRuleGenerator:
    """Generates Sigma detection rules from CyberSentinel findings."""

    def generate(self, finding: Finding) -> str:
        """Generate a single Sigma rule YAML string from a Finding.

        Args:
            finding: The Finding object to convert to a Sigma rule

        Returns:
            A properly formatted Sigma rule in YAML format
        """
        return self._build_sigma_rule(finding)

    def generate_batch(self, findings: list[Finding]) -> str:
        """Generate multiple Sigma rules.

        Args:
            findings: List of Finding objects

        Returns:
            Multiple Sigma rules separated by newlines
        """
        rules = []
        for finding in findings:
            rules.append(self.generate(finding))
            rules.append("---")
        return "\n".join(rules[:-1])  # Remove trailing separator

    def _build_sigma_rule(self, finding: Finding) -> str:
        """Build complete Sigma rule for a finding."""
        sigma_level = SEVERITY_TO_SIGMA_LEVEL.get(
            finding.severity, "medium"
        )

        # Extract meaningful detection content
        logsource = self._determine_logsource(finding)
        selection = self._build_selection(finding, logsource)
        condition = "selection"

        # Build tags
        tags = []
        if finding.mitre_techniques:
            for technique in finding.mitre_techniques:
                technique_id = technique.split(".")[-1] if "." in technique else technique
                tactic = ATTACK_TECHNIQUE_TACTICS.get(
                    technique_id, "defense_evasion"
                )
                tags.append(f"attack.{technique_id.lower()}")
                tags.append(f"attack.{tactic}")
        else:
            tags.append("attack.t1566")  # Default to Phishing
            tags.append("attack.initial_access")

        # Add confidence-based tags
        if finding.confidence == "high":
            tags.append("detection.system_detection")
        elif finding.confidence == "medium":
            tags.append("detection.endpoint_detection_edr")
        else:
            tags.append("detection.host_enrichment")

        # Build false positives list
        false_positives = self._extract_false_positives(finding)

        # Build YAML
        rule_parts = [
            "title: " + self._escape_yaml(finding.title),
            "id: " + self._generate_id(finding),
            "status: experimental",
            "description: " + self._escape_yaml(finding.description),
            f"date: {datetime.now().strftime('%Y/%m/%d')}",
            f"logsource:",
            f"    category: {logsource['category']}",
        ]

        if "product" in logsource:
            rule_parts.append(f"    product: {logsource['product']}")
        if "service" in logsource:
            rule_parts.append(f"    service: {logsource['service']}")

        rule_parts.append("detection:")
        rule_parts.append(f"    selection:{selection}")
        rule_parts.append(f"    condition: {condition}")

        rule_parts.append(f"level: {sigma_level}")

        if tags:
            rule_parts.append("tags:")
            for tag in list(set(tags)):
                rule_parts.append(f"    - {tag}")

        if finding.cve_ids:
            rule_parts.append("references:")
            for cve in finding.cve_ids:
                rule_parts.append(f"    - https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}")

        rule_parts.append("falsepositives:")
        for fp in false_positives:
            rule_parts.append(f"    - {self._escape_yaml(fp)}")

        return "\n".join(rule_parts)

    def _determine_logsource(self, finding: Finding) -> dict:
        """Determine logsource category based on finding type and CWE."""
        if finding.cwe_ids:
            cwe = finding.cwe_ids[0]
            logsource_type = CWE_TO_LOGSOURCE.get(cwe, "process")
        else:
            logsource_type = "process"

        logsource_map = {
            "web": {"category": "web_application_firewall"},
            "auth": {"category": "authentication", "product": "generic"},
            "network": {"category": "network_connection"},
            "file": {"category": "file_event"},
            "process": {"category": "process_creation"},
        }

        return logsource_map.get(logsource_type, {"category": "process_creation"})

    def _build_selection(self, finding: Finding, logsource: dict) -> str:
        """Build the selection clause based on finding content."""
        # Extract keywords and patterns from finding
        keywords = []

        # Extract from title
        title_words = re.findall(r'\b[A-Za-z]+\b', finding.title)
        keywords.extend([w.lower() for w in title_words if len(w) > 3][:3])

        # Extract from description
        desc_words = re.findall(r'\b[A-Za-z]+\b', finding.description)
        keywords.extend([w.lower() for w in desc_words if len(w) > 4][:3])

        # Extract suspicious patterns for specific categories
        if "sql" in finding.title.lower() or "sql" in finding.description.lower():
            keywords.extend(["union", "select", "insert", "drop"])
        elif "injection" in finding.title.lower():
            keywords.extend(["<script>", "eval", "${", "exec"])
        elif "command" in finding.title.lower():
            keywords.extend(["powershell", "cmd", "bash", "sh"])
        elif "authentication" in finding.title.lower():
            keywords.extend(["password", "credential", "token", "session"])

        keywords = list(set(keywords))[:5]

        # Build YAML selection
        selection_items = []
        for kw in keywords:
            selection_items.append(
                f"        - '{kw}'"
            )

        if not selection_items:
            selection_items.append("        - 'suspicious'")

        return "\n" + "\n".join(selection_items)

    def _extract_false_positives(self, finding: Finding) -> list:
        """Extract or generate list of likely false positives."""
        fps = []

        # Default false positives based on finding type
        if "authentication" in finding.title.lower():
            fps = [
                "Legitimate account lockouts",
                "Test environment authentication attempts",
                "Automated security scanning",
            ]
        elif "injection" in finding.title.lower():
            fps = [
                "Security scanner activity",
                "Penetration testing exercises",
                "Development environments testing payloads",
            ]
        elif "command" in finding.title.lower():
            fps = [
                "System administration tasks",
                "Scheduled maintenance scripts",
                "Legitimate system utilities",
            ]
        else:
            fps = [
                "Authorized testing",
                "System maintenance",
                "Security scanning tools",
            ]

        return fps

    def _escape_yaml(self, text: str) -> str:
        """Escape text for YAML values."""
        if any(char in text for char in [':', '"', "'", '\n', '|', '>']):
            return f'"{text.replace(chr(34), chr(92) + chr(34))}"'
        return text

    def _generate_id(self, finding: Finding) -> str:
        """Generate a UUIv4-style ID from finding attributes."""
        import hashlib
        content = f"{finding.title}{finding.affected_component}{finding.cve_ids}"
        hash_obj = hashlib.md5(content.encode())
        hash_hex = hash_obj.hexdigest()
        return f"{hash_hex[:8]}-{hash_hex[8:12]}-{hash_hex[12:16]}-{hash_hex[16:20]}-{hash_hex[20:32]}"


class YaraRuleGenerator:
    """Generates YARA detection rules from CyberSentinel findings."""

    def generate(self, finding: Finding) -> str:
        """Generate a single YARA rule string from a Finding.

        Args:
            finding: The Finding object to convert to a YARA rule

        Returns:
            A properly formatted YARA rule
        """
        return self._build_yara_rule(finding)

    def generate_batch(self, findings: list[Finding]) -> str:
        """Generate multiple YARA rules.

        Args:
            findings: List of Finding objects

        Returns:
            Multiple YARA rules separated by newlines
        """
        rules = []
        for finding in findings:
            rules.append(self.generate(finding))
            rules.append("")
        return "\n".join(rules).strip()

    def _build_yara_rule(self, finding: Finding) -> str:
        """Build complete YARA rule for a finding."""
        rule_name = self._sanitize_rule_name(finding.title)

        # Extract patterns
        strings = self._extract_patterns(finding)
        condition = self._build_condition(strings)

        # Build meta section
        severity = finding.severity.value
        author = "CyberSentinel"
        description = finding.description[:100]

        rule_parts = [
            f'rule {rule_name} {{',
            "    meta:",
            f'        author = "{author}"',
            f'        description = "{self._escape_string(description)}"',
            f'        severity = "{severity}"',
            f'        confidence = "{finding.confidence}"',
        ]

        # Add CVE references
        if finding.cve_ids:
            refs = ", ".join(finding.cve_ids)
            rule_parts.append(f'        reference = "{refs}"')

        # Add MITRE ATT&CK references
        if finding.mitre_techniques:
            techniques = ", ".join(finding.mitre_techniques)
            rule_parts.append(f'        mitre_techniques = "{techniques}"')

        rule_parts.append("    strings:")

        # Add patterns as strings
        for idx, pattern in enumerate(strings[:10], 1):
            escaped = self._escape_string(pattern)
            rule_parts.append(f'        $str{idx} = "{escaped}" nocase')

        rule_parts.append("    condition:")
        rule_parts.append(f"        {condition}")
        rule_parts.append("}")

        return "\n".join(rule_parts)

    def _extract_patterns(self, finding: Finding) -> list:
        """Extract detection patterns from finding."""
        patterns = []

        # Extract from title
        if "sql" in finding.title.lower():
            patterns.extend([
                "union all select",
                "union select",
                "; select",
                "' or '1'='1",
                "' or 1=1",
                "exec(",
                "execute(",
            ])

        if "xss" in finding.title.lower() or "cross-site script" in finding.title.lower():
            patterns.extend([
                "<script",
                "javascript:",
                "onerror=",
                "onload=",
                "onclick=",
                "eval(",
            ])

        if "command" in finding.title.lower() or "injection" in finding.title.lower():
            patterns.extend([
                "powershell.exe",
                "cmd.exe",
                "/bin/bash",
                "/bin/sh",
                "nc -",
                "bash -i",
            ])

        if "authentication" in finding.title.lower() or "credential" in finding.title.lower():
            patterns.extend([
                "password",
                "authorization",
                "bearer",
                "api_key",
                "secret",
            ])

        if "exploit" in finding.title.lower():
            patterns.extend([
                "shellcode",
                "payload",
                "nops",
                "0x90 0x90",
            ])

        # Add patterns from evidence if available
        if finding.evidence:
            evidence_patterns = re.findall(
                r"(?:payload|string|pattern|indicator)[:\s]+([^\n]+)",
                finding.evidence,
                re.IGNORECASE
            )
            patterns.extend(evidence_patterns[:3])

        # Default patterns
        if not patterns:
            keywords = finding.title.split()[:2]
            patterns = [kw for kw in keywords if len(kw) > 3]
            if not patterns:
                patterns = ["suspicious", "malicious"]

        return list(set(patterns))[:15]

    def _build_condition(self, strings: list) -> str:
        """Build the condition clause."""
        if len(strings) == 1:
            return "$str1"
        elif len(strings) <= 3:
            return f"any of ($str*)"
        else:
            return f"{min(3, len(strings))} of ($str*)"

    def _sanitize_rule_name(self, title: str) -> str:
        """Convert title to valid YARA rule name."""
        name = re.sub(r'[^a-zA-Z0-9_]', '_', title)
        name = re.sub(r'_+', '_', name)
        name = name.strip('_')
        # Ensure it starts with a letter
        if name and not name[0].isalpha():
            name = 'rule_' + name
        return name[:64] if name else "unknown_rule"

    def _escape_string(self, text: str) -> str:
        """Escape string for YARA rule."""
        text = str(text)
        text = text.replace('\\', '\\\\')
        text = text.replace('"', '\\"')
        text = text.replace('\n', '\\n')
        text = text.replace('\r', '\\r')
        text = text.replace('\t', '\\t')
        return text


class DetectionRuleBuilder:
    """High-level interface for generating detection rules."""

    def __init__(self):
        """Initialize with Sigma and YARA generators."""
        self.sigma = SigmaRuleGenerator()
        self.yara = YaraRuleGenerator()

    def generate_sigma_rules(self, findings: list[Finding]) -> dict:
        """Generate Sigma rules for findings.

        Args:
            findings: List of Finding objects

        Returns:
            Dictionary with 'single_rules' and 'batch' keys containing rule strings
        """
        return {
            "single_rules": [self.sigma.generate(f) for f in findings],
            "batch": self.sigma.generate_batch(findings),
        }

    def generate_yara_rules(self, findings: list[Finding]) -> dict:
        """Generate YARA rules for findings.

        Args:
            findings: List of Finding objects

        Returns:
            Dictionary with 'single_rules' and 'batch' keys containing rule strings
        """
        return {
            "single_rules": [self.yara.generate(f) for f in findings],
            "batch": self.yara.generate_batch(findings),
        }

    def generate_all(self, findings: list[Finding]) -> dict:
        """Generate both Sigma and YARA rules.

        Args:
            findings: List of Finding objects

        Returns:
            Dictionary with 'sigma' and 'yara' keys, each containing rule data
        """
        return {
            "sigma": self.generate_sigma_rules(findings),
            "yara": self.generate_yara_rules(findings),
        }
