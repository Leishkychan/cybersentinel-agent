"""
Log Parser Agent for CyberSentinel

Analyzes security-relevant logs (syslog, Apache/Nginx, Windows Event Log)
and detects anomalies, attacks, and indicators of compromise.
"""

import re
from collections import defaultdict
from datetime import datetime
from typing import Optional
from xml.etree import ElementTree as ET

from cybersentinel.agents.base import BaseAgent
from cybersentinel.models.finding import Finding, Severity


class LogParserAgent(BaseAgent):
    """
    Security log analysis agent for anomaly and indicator detection.

    Supports:
    - Syslog/auth.log (failed logins, privilege escalation, SSH anomalies)
    - Apache/Nginx access logs (SQL injection, path traversal, scanning, floods)
    - Windows Event Log XML (failed logons, privilege use, service installation)
    """

    name = "log_parser"
    description = "Security log analysis — anomaly and indicator detection"

    # Detection thresholds
    BRUTE_FORCE_THRESHOLD = 5  # Failed logins from same IP in window
    SQL_INJECTION_PATTERNS = [
        r"(?i)(union\s+select|select\s+from|insert\s+into|delete\s+from|drop\s+table)",
        r"(?i)(\bor\b\s+1\s*=\s*1|\bor\b\s+true)",
        r"(?i)(;\s*drop|;\s*delete|;\s*update)",
        r"(?i)(%27|%22).{0,20}(union|select|or)",
    ]

    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.",
        r"%2e%2e",
        r"\.\.%2f",
    ]

    SCANNER_USER_AGENTS = [
        "nikto",
        "sqlmap",
        "nmap",
        "masscan",
        "nessus",
        "openvas",
        "metasploit",
        "burp",
        "zaproxy",
        "acunetix",
        "qualys",
        "masscan",
        "aquatone",
        "wpscan",
        "nuclei",
    ]

    # Windows Event Log IDs
    WINDOWS_FAILED_LOGON = 4625
    WINDOWS_ACCOUNT_LOCKOUT = 4740
    WINDOWS_PRIVILEGE_USE = 4672
    WINDOWS_SERVICE_INSTALL = 7045
    WINDOWS_AUDIT_CLEARED = 1102

    def analyze(self, target: str, context: dict) -> list[Finding]:
        """
        Analyze security logs for anomalies and indicators.

        Args:
            target: Identifier for the log source (hostname, application name)
            context: Dictionary with 'log_content' (str) and 'log_type' (str)

        Returns:
            List of Finding objects detected in the logs
        """
        self.validate(target, f"Log analysis of {target}")

        log_content = context.get("log_content", "")
        log_type = context.get("log_type", "").lower()

        if not log_content:
            self.log(f"No log content provided for {target}")
            return []

        self.findings = []

        # Route to appropriate parser based on log type
        if "syslog" in log_type or "auth" in log_type:
            self._parse_syslog(log_content, target)
        elif "apache" in log_type or "nginx" in log_type or "access" in log_type:
            self._parse_access_log(log_content, target)
        elif "windows" in log_type or "xml" in log_type or "event" in log_type:
            self._parse_windows_event_log(log_content, target)
        else:
            self.log(f"Unknown log type: {log_type}")

        self.log(f"Analyzed {log_type} for {target}: {len(self.findings)} findings")
        return self.findings

    def _parse_syslog(self, log_content: str, target: str) -> None:
        """
        Parse syslog/auth.log for security indicators.

        Detects:
        - Brute force attempts (failed logins)
        - Privilege escalation (su/sudo usage)
        - SSH anomalies
        """
        lines = log_content.split("\n")

        # Track failed logins per source IP
        failed_logins = defaultdict(int)
        failed_login_lines = defaultdict(list)

        for line in lines:
            # Detect failed SSH logins
            if re.search(r"(Failed password|Invalid user|authentication failure)", line, re.IGNORECASE):
                # Extract source IP
                ip_match = re.search(r"from\s+(\d+\.\d+\.\d+\.\d+)|rhost=(\d+\.\d+\.\d+\.\d+)", line)
                if ip_match:
                    source_ip = ip_match.group(1) or ip_match.group(2)
                    failed_logins[source_ip] += 1
                    failed_login_lines[source_ip].append(line)

            # Detect sudo/su privilege escalation
            if re.search(r"sudo\[|su\[", line, re.IGNORECASE):
                self._create_finding(
                    title="Privilege Escalation Attempt",
                    description=f"Detected privilege escalation attempt via sudo/su on {target}",
                    severity=Severity.MEDIUM,
                    mitre_technique="T1548",
                    cwe="CWE-269",
                    remediation="Monitor and restrict sudo/su usage; enable auditing of privilege changes",
                    log_line=line,
                    target=target,
                )

            # Detect SSH key-based anomalies
            if re.search(r"Invalid publickey|publickey denied", line, re.IGNORECASE):
                self._create_finding(
                    title="SSH Public Key Authentication Anomaly",
                    description=f"Unusual SSH public key authentication on {target}",
                    severity=Severity.LOW,
                    mitre_technique="T1098",
                    cwe="CWE-287",
                    remediation="Review SSH key policies; monitor authorized_keys changes",
                    log_line=line,
                    target=target,
                )

            # Detect SSH port forwarding
            if re.search(r"Received request for.*forwarding|Allocated port", line, re.IGNORECASE):
                self._create_finding(
                    title="SSH Port Forwarding Detected",
                    description=f"SSH port forwarding request on {target}",
                    severity=Severity.MEDIUM,
                    mitre_technique="T1572",
                    cwe="CWE-94",
                    remediation="Disable SSH tunneling if not required; monitor for unauthorized forwarding",
                    log_line=line,
                    target=target,
                )

        # Check for brute force attacks
        for source_ip, count in failed_logins.items():
            if count >= self.BRUTE_FORCE_THRESHOLD:
                self._create_finding(
                    title="Brute Force Attack Detected",
                    description=f"Multiple failed login attempts ({count}) from {source_ip} targeting {target}",
                    severity=Severity.HIGH,
                    mitre_technique="T1110",
                    cwe="CWE-307",
                    remediation="Implement rate limiting; enable account lockout; consider fail2ban or similar tools",
                    source_ip=source_ip,
                    target=target,
                )

    def _parse_access_log(self, log_content: str, target: str) -> None:
        """
        Parse Apache/Nginx access logs for security indicators.

        Detects:
        - SQL injection attempts
        - Path traversal attempts
        - Scanner fingerprints
        - HTTP floods
        - Suspicious status codes
        """
        lines = log_content.split("\n")

        # Track request rates per IP
        ip_request_counts = defaultdict(int)
        ip_lines = defaultdict(list)

        # Track status code bursts
        status_code_counts = defaultdict(lambda: defaultdict(int))

        for line in lines:
            if not line.strip():
                continue

            # Extract source IP and request details
            ip_match = re.search(r"^(\d+\.\d+\.\d+\.\d+)", line)
            user_agent_match = re.search(r'"([^"]*)"$', line)

            if not ip_match:
                continue

            source_ip = ip_match.group(1)
            ip_request_counts[source_ip] += 1
            ip_lines[source_ip].append(line)

            # Extract status code
            status_match = re.search(r'\s(\d{3})\s', line)
            if status_match:
                status_code = status_match.group(1)
                status_code_counts[source_ip][status_code] += 1

            # Detect SQL injection attempts in URL
            for pattern in self.SQL_INJECTION_PATTERNS:
                if re.search(pattern, line):
                    # Extract URL from log line
                    url_match = re.search(r'"(?:GET|POST|PUT|DELETE)\s+([^\s]+)', line)
                    url = url_match.group(1) if url_match else "unknown"

                    self._create_finding(
                        title="SQL Injection Attempt Detected",
                        description=f"Potential SQL injection attack from {source_ip} targeting {target}: {url}",
                        severity=Severity.HIGH,
                        mitre_technique="T1190",
                        cwe="CWE-89",
                        remediation="Use parameterized queries; implement WAF rules; validate input; update database drivers",
                        source_ip=source_ip,
                        target=target,
                        log_line=line,
                    )
                    break

            # Detect path traversal attempts
            for pattern in self.PATH_TRAVERSAL_PATTERNS:
                if re.search(pattern, line):
                    url_match = re.search(r'"(?:GET|POST|PUT|DELETE)\s+([^\s]+)', line)
                    url = url_match.group(1) if url_match else "unknown"

                    self._create_finding(
                        title="Path Traversal Attack Detected",
                        description=f"Path traversal attempt from {source_ip} targeting {target}: {url}",
                        severity=Severity.HIGH,
                        mitre_technique="T1083",
                        cwe="CWE-22",
                        remediation="Normalize URLs; restrict file access; implement input validation; use WAF rules",
                        source_ip=source_ip,
                        target=target,
                        log_line=line,
                    )
                    break

            # Detect scanner user agents
            if user_agent_match:
                user_agent = user_agent_match.group(1).lower()
                for scanner in self.SCANNER_USER_AGENTS:
                    if scanner in user_agent:
                        self._create_finding(
                            title="Security Scanner Detected",
                            description=f"Scanning tool '{scanner}' detected from {source_ip} targeting {target}",
                            severity=Severity.MEDIUM,
                            mitre_technique="T1592",
                            cwe="CWE-200",
                            remediation="Block scanner IPs at firewall; review scan scope; investigate for unauthorized scans",
                            source_ip=source_ip,
                            target=target,
                            log_line=line,
                        )
                        break

        # Detect HTTP floods
        flood_threshold = 100  # requests per IP in log window
        for source_ip, count in ip_request_counts.items():
            if count > flood_threshold:
                self._create_finding(
                    title="HTTP Flood Attack Detected",
                    description=f"High request rate ({count} requests) from {source_ip} targeting {target}",
                    severity=Severity.HIGH,
                    mitre_technique="T1498",
                    cwe="CWE-770",
                    remediation="Implement rate limiting; configure DDoS protection; block source IP at firewall",
                    source_ip=source_ip,
                    target=target,
                )

        # Detect suspicious status code bursts (403/401)
        for source_ip, codes in status_code_counts.items():
            forbidden_count = codes.get('403', 0) + codes.get('401', 0)
            if forbidden_count > 10:
                self._create_finding(
                    title="Suspicious Status Code Burst Detected",
                    description=f"High rate of 403/401 responses ({forbidden_count}) from {source_ip} to {target}",
                    severity=Severity.MEDIUM,
                    mitre_technique="T1110",
                    cwe="CWE-307",
                    remediation="Review access controls; investigate for enumeration attempts; enable rate limiting",
                    source_ip=source_ip,
                    target=target,
                )

    def _parse_windows_event_log(self, log_content: str, target: str) -> None:
        """
        Parse Windows Event Log (XML format) for security indicators.

        Detects:
        - Failed logons (4625)
        - Account lockouts (4740)
        - Privilege escalation (4672)
        - Service installation (7045)
        - Audit log clearing (1102)
        """
        try:
            root = ET.fromstring(log_content)
        except ET.ParseError:
            self.log(f"Failed to parse Windows Event Log XML for {target}")
            return

        # Track failed logons per account
        failed_logons = defaultdict(int)
        failed_logon_details = defaultdict(list)

        for event in root.findall(".//Event"):
            # Extract event ID
            event_id_elem = event.find(".//EventID")
            if event_id_elem is None:
                continue

            try:
                event_id = int(event_id_elem.text)
            except (ValueError, TypeError):
                continue

            # Extract computer name
            computer = event.find(".//Computer")
            computer_name = computer.text if computer is not None else "unknown"

            # Event ID 4625: Failed Logon
            if event_id == self.WINDOWS_FAILED_LOGON:
                target_account = self._extract_xml_field(event, "TargetUserName")
                source_ip = self._extract_xml_field(event, "IpAddress")
                logon_type = self._extract_xml_field(event, "LogonType")

                if target_account:
                    failed_logons[target_account] += 1
                    failed_logon_details[target_account].append({
                        "source_ip": source_ip,
                        "logon_type": logon_type,
                    })

                # Alert on suspicious logon types
                if logon_type in ["3", "10"]:  # Network, RDP
                    self._create_finding(
                        title="Failed Remote Logon Detected",
                        description=f"Failed {self._get_logon_type_name(logon_type)} logon for {target_account} on {target}",
                        severity=Severity.MEDIUM,
                        mitre_technique="T1110",
                        cwe="CWE-307",
                        remediation="Review user access attempts; implement IP-based restrictions; enable MFA",
                        source_ip=source_ip,
                        target=target,
                        event_id=event_id,
                    )

            # Event ID 4740: Account Lockout
            elif event_id == self.WINDOWS_ACCOUNT_LOCKOUT:
                target_account = self._extract_xml_field(event, "TargetUserName")

                self._create_finding(
                    title="Account Lockout Detected",
                    description=f"Account '{target_account}' locked out on {target} due to failed login attempts",
                    severity=Severity.MEDIUM,
                    mitre_technique="T1110",
                    cwe="CWE-307",
                    remediation="Review failed login attempts; unlock account if legitimate; enable monitoring",
                    target=target,
                    event_id=event_id,
                )

            # Event ID 4672: Privilege Use (Special Logon)
            elif event_id == self.WINDOWS_PRIVILEGE_USE:
                subject_user = self._extract_xml_field(event, "SubjectUserName")

                self._create_finding(
                    title="Privileged Logon Detected",
                    description=f"Privileged logon for user '{subject_user}' on {target}",
                    severity=Severity.LOW,
                    mitre_technique="T1078",
                    cwe="CWE-269",
                    remediation="Monitor privileged account usage; implement least privilege; use PAM solutions",
                    target=target,
                    event_id=event_id,
                )

            # Event ID 7045: Service Installation
            elif event_id == self.WINDOWS_SERVICE_INSTALL:
                service_name = self._extract_xml_field(event, "ServiceName")
                service_filename = self._extract_xml_field(event, "ServiceFileName")

                self._create_finding(
                    title="New Service Installation Detected",
                    description=f"Service '{service_name}' installed on {target}: {service_filename}",
                    severity=Severity.MEDIUM,
                    mitre_technique="T1543",
                    cwe="CWE-94",
                    remediation="Review service installation; verify against change logs; disable if unauthorized",
                    target=target,
                    event_id=event_id,
                )

            # Event ID 1102: Audit Log Cleared
            elif event_id == self.WINDOWS_AUDIT_CLEARED:
                subject_user = self._extract_xml_field(event, "SubjectUserName")

                self._create_finding(
                    title="Audit Log Cleared (Evidence Destruction)",
                    description=f"Security audit log cleared by '{subject_user}' on {target}",
                    severity=Severity.CRITICAL,
                    mitre_technique="T1070",
                    cwe="CWE-1145",
                    remediation="Investigate user access; enable immutable audit logs; restrict log deletion permissions",
                    target=target,
                    event_id=event_id,
                )

        # Check for brute force on Windows (multiple failed logons for single account)
        for account, count in failed_logons.items():
            if count >= self.BRUTE_FORCE_THRESHOLD:
                details = failed_logon_details[account]
                source_ips = set(d["source_ip"] for d in details if d["source_ip"])

                self._create_finding(
                    title="Brute Force Attack Detected",
                    description=f"Multiple failed logons ({count}) for account '{account}' on {target} from {', '.join(source_ips) if source_ips else 'various sources'}",
                    severity=Severity.HIGH,
                    mitre_technique="T1110",
                    cwe="CWE-307",
                    remediation="Implement account lockout policy; configure logon attempt thresholds; monitor for credential stuffing",
                    target=target,
                    event_id=self.WINDOWS_FAILED_LOGON,
                )

    def _extract_xml_field(self, event: ET.Element, field_name: str) -> Optional[str]:
        """
        Extract a field value from Windows Event Log XML.

        Args:
            event: Event XML element
            field_name: Name of the field to extract

        Returns:
            Field value or None
        """
        for data in event.findall(".//Data"):
            if data.get("Name") == field_name:
                return data.text
        return None

    def _get_logon_type_name(self, logon_type: str) -> str:
        """
        Get human-readable name for Windows logon type.

        Args:
            logon_type: Windows logon type number

        Returns:
            Human-readable name
        """
        logon_types = {
            "2": "Interactive",
            "3": "Network",
            "4": "Batch",
            "5": "Service",
            "7": "Unlock",
            "8": "NetworkCleartext",
            "9": "NewCredentials",
            "10": "RDP",
            "11": "CachedInteractive",
        }
        return logon_types.get(logon_type, f"Unknown({logon_type})")

    def _create_finding(
        self,
        title: str,
        description: str,
        severity: Severity,
        mitre_technique: str,
        cwe: str,
        remediation: str,
        target: str,
        source_ip: Optional[str] = None,
        log_line: Optional[str] = None,
        event_id: Optional[int] = None,
    ) -> None:
        """
        Create and store a Finding object.

        Args:
            title: Finding title
            description: Finding description
            severity: Severity level
            mitre_technique: MITRE ATT&CK technique ID
            cwe: CWE identifier
            remediation: Remediation steps
            target: Target/source identifier
            source_ip: Optional source IP address
            log_line: Optional original log line
            event_id: Optional Windows Event ID
        """
        finding = Finding(
            title=title,
            description=description,
            severity=severity,
            agent_source="log_parser",
            mitre_techniques=[mitre_technique],
            cwe_ids=[cwe],
            remediation=remediation,
            affected_component=target,
            evidence=f"source_ip={source_ip}, event_id={event_id}" if source_ip or event_id else "",
        )
        self.findings.append(finding)
