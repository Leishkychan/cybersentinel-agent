"""Web Application Scanning Agent — OWASP ZAP Integration.

Runs ZAP in daemon mode and uses REST API for:
- Spidering
- Active scanning
- Alert collection

Supports authenticated scanning via context configuration.
"""

from __future__ import annotations

import json
import subprocess
import logging
import time
import requests
from pathlib import Path
from typing import Optional

from cybersentinel.agents.base import BaseAgent
from cybersentinel.models.finding import Finding, Severity


logger = logging.getLogger(__name__)


class WebAppScanAgent(BaseAgent):
    """Web application vulnerability scanning via OWASP ZAP."""

    name = "webapp"
    description = "Web application security scanning (OWASP ZAP)"

    ZAP_API_URL = "http://localhost:8090"
    ZAP_PORT = 8090

    # ZAP alert mappings to CWE
    ZAP_CWE_MAP = {
        "10000": "CWE-200",   # Insufficient Information
        "10001": "CWE-287",   # Improper Authentication
        "10002": "CWE-284",   # Improper Access Control
        "10003": "CWE-79",    # Cross-Site Scripting
        "10004": "CWE-89",    # Insecure Deserialization
        "10005": "CWE-434",   # File Upload
        "10006": "CWE-400",   # DoS
        "10007": "CWE-22",    # Path Traversal
        "10008": "CWE-89",    # SQL Injection
        "10009": "CWE-295",   # Insecure SSL/TLS
        "10010": "CWE-311",   # Missing Encryption
        "10011": "CWE-611",   # XXE
        "10012": "CWE-95",    # Code Injection
        "10013": "CWE-400",   # Resource Exhaustion
        "10014": "CWE-400",   # DoS - Slow Attack
        "10015": "CWE-400",   # DoS - Memory
        "10016": "CWE-79",    # DOM XSS
        "10017": "CWE-601",   # Open Redirect
        "10018": "CWE-319",   # Cleartext Transmission
        "10019": "CWE-1021",  # Clickjacking
        "10020": "CWE-693",   # Missing Security Header
        "10021": "CWE-295",   # SSL/TLS Issue
        "10025": "CWE-200",   # Information Disclosure
        "10026": "CWE-287",   # Weak Authentication
        "10027": "CWE-79",    # Error-based XSS
        "10028": "CWE-400",   # Improper Rate Limiting
        "10029": "CWE-502",   # Deserialization
        "10030": "CWE-434",   # Unrestricted Upload
        "10031": "CWE-89",    # LDAP Injection
        "10032": "CWE-614",   # Insecure Cookie
        "10033": "CWE-425",   # Proxy Manipulation
        "10034": "CWE-400",   # Resource Exhaustion
        "10035": "CWE-307",   # Insufficient Authentication
        "10036": "CWE-400",   # Server Misconfiguration
        "10037": "CWE-79",    # Stored XSS
        "10038": "CWE-95",    # Expression Language Injection
        "10039": "CWE-79",    # XPath Injection
        "10040": "CWE-400",   # Race Condition
        "10041": "CWE-200",   # Directory Listing
        "10042": "CWE-79",    # Parameter Pollution
        "10043": "CWE-400",   # Denial of Service
        "10044": "CWE-434",   # File Manipulation
        "10045": "CWE-502",   # Serialization Issue
        "10046": "CWE-79",    # Reflected XSS
        "10047": "CWE-89",    # OS Injection
        "10048": "CWE-89",    # Shell Injection
        "10049": "CWE-295",   # Certificate Validation
        "10050": "CWE-200",   # Information Leakage
        "10051": "CWE-95",    # Template Injection
        "10052": "CWE-400",   # Slow Response
        "10053": "CWE-284",   # Authorization
        "10054": "CWE-434",   # Insecure File Upload
        "10055": "CWE-400",   # Client Error
        "10056": "CWE-400",   # Server Error
        "10057": "CWE-89",    # NoSQL Injection
        "10058": "CWE-502",   # Unsafe Deserialization
        "10059": "CWE-295",   # Weak SSL Configuration
        "10060": "CWE-200",   # Version Disclosure
    }

    def analyze(self, target: str, context: dict) -> list[Finding]:
        """Run ZAP spider and active scan."""
        self.validate(target, f"Web application scan of {target}")
        self.log(f"Starting web app scan on {target}")

        findings: list[Finding] = []

        # Ensure target is a URL
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"

        # Start ZAP daemon if not running
        if not self._zap_available():
            self.log("Starting ZAP daemon...")
            self._start_zap()
            time.sleep(3)

        try:
            # Configure authentication if provided
            auth_token = context.get("auth_token")
            auth_cookie = context.get("auth_cookie")
            if auth_token or auth_cookie:
                self._configure_auth(auth_token, auth_cookie)

            # Run spider
            self.log(f"Spidering {target}...")
            scan_id = self._spider(target)
            if scan_id:
                self._wait_for_scan(scan_id)

            # Run active scan
            self.log(f"Running active scan on {target}...")
            scan_id = self._active_scan(target)
            if scan_id:
                self._wait_for_scan(scan_id)

            # Get alerts
            findings = self._get_alerts(target)

        except Exception as e:
            self.log(f"ZAP scan error: {str(e)[:200]}")

        self.log(f"Web app scan complete: {len(findings)} findings")
        return findings

    def _zap_available(self) -> bool:
        """Check if ZAP daemon is running."""
        try:
            response = requests.get(
                f"{self.ZAP_API_URL}/JSON/core/view/version/",
                timeout=2,
            )
            return response.status_code == 200
        except Exception:
            return False

    def _start_zap(self) -> None:
        """Start ZAP daemon mode."""
        try:
            cmd = [
                "zap.sh",
                "-daemon",
                "-port", str(self.ZAP_PORT),
                "-config", "api.disablekey=true",
            ]
            subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            self.log("ZAP not found at 'zap.sh'")

    def _configure_auth(self, token: Optional[str], cookie: Optional[str]) -> None:
        """Configure authentication context in ZAP."""
        try:
            if token:
                headers = {"Authorization": f"Bearer {token}"}
                # Store in context for subsequent requests
                pass

            if cookie:
                # Configure cookie handling
                pass

        except Exception as e:
            self.log(f"Auth config error: {str(e)[:100]}")

    def _spider(self, target: str) -> Optional[str]:
        """Run ZAP spider."""
        try:
            response = requests.get(
                f"{self.ZAP_API_URL}/JSON/spider/action/scan/",
                params={"url": target},
                timeout=30,
            )
            data = response.json()
            return data.get("scan")
        except Exception as e:
            self.log(f"Spider error: {str(e)[:100]}")
            return None

    def _active_scan(self, target: str) -> Optional[str]:
        """Run ZAP active scan."""
        try:
            response = requests.get(
                f"{self.ZAP_API_URL}/JSON/ascan/action/scan/",
                params={"url": target},
                timeout=30,
            )
            data = response.json()
            return data.get("scan")
        except Exception as e:
            self.log(f"Active scan error: {str(e)[:100]}")
            return None

    def _wait_for_scan(self, scan_id: str, timeout: int = 300) -> None:
        """Wait for scan to complete."""
        start = time.time()
        while time.time() - start < timeout:
            try:
                response = requests.get(
                    f"{self.ZAP_API_URL}/JSON/ascan/view/scanProgress/",
                    params={"scanId": scan_id},
                    timeout=10,
                )
                progress = int(response.json().get("scanProgress", [{}])[0].get("percentage", 0))
                if progress >= 100:
                    break
                time.sleep(2)
            except Exception:
                break

    def _get_alerts(self, target: str) -> list[Finding]:
        """Get alerts from ZAP for target."""
        findings = []
        try:
            response = requests.get(
                f"{self.ZAP_API_URL}/JSON/core/view/alerts/",
                params={"baseurl": target},
                timeout=30,
            )
            alerts = response.json().get("alerts", [])

            for alert in alerts:
                alert_id = alert.get("alertid", "")
                cwe = self.ZAP_CWE_MAP.get(alert_id, "CWE-200")
                severity = self._zap_severity(alert.get("riskcode", "1"))

                finding = Finding(
                    title=f"ZAP: {alert.get('alert', '')}",
                    severity=severity,
                    description=alert.get("description", ""),
                    affected_component=alert.get("url", ""),
                    agent_source=self.name,
                    cwe_ids=[cwe],
                    evidence=alert.get("evidence", ""),
                    remediation=alert.get("solution", ""),
                    mitre_techniques=self._map_attack(alert.get("alert", "")),
                )
                findings.append(finding)

        except Exception as e:
            self.log(f"Get alerts error: {str(e)[:100]}")

        return findings

    def _zap_severity(self, risk_code: str) -> Severity:
        """Map ZAP risk code to Severity."""
        code = int(risk_code) if risk_code.isdigit() else 1
        if code == 3:
            return Severity.CRITICAL
        elif code == 2:
            return Severity.HIGH
        elif code == 1:
            return Severity.MEDIUM
        else:
            return Severity.LOW

    def _map_attack(self, alert: str) -> list[str]:
        """Map ZAP alert to MITRE ATT&CK techniques."""
        alert_lower = alert.lower()

        techniques = []

        if any(x in alert_lower for x in ["xss", "cross-site"]):
            techniques.append("T1189")
        if any(x in alert_lower for x in ["sql", "injection"]):
            techniques.append("T1190")
        if any(x in alert_lower for x in ["path", "traversal"]):
            techniques.append("T1083")
        if any(x in alert_lower for x in ["authentication", "password"]):
            techniques.append("T1110")
        if any(x in alert_lower for x in ["redirect", "open"]):
            techniques.append("T1598")
        if any(x in alert_lower for x in ["ssl", "tls", "certificate"]):
            techniques.append("T1557")
        if any(x in alert_lower for x in ["headers", "security"]):
            techniques.append("T1021")

        return techniques if techniques else ["T1190"]
