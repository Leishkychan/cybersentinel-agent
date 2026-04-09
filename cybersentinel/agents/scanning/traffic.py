"""Traffic Analysis Agent — Network Traffic Interception and Analysis.

Uses mitmproxy to intercept and analyze HTTP/HTTPS traffic for:
- Insecure cookies (missing Secure/HttpOnly flags)
- Missing security headers
- Sensitive data in URLs
- Mixed content (HTTPS loading HTTP)
- Unencrypted traffic
"""

from __future__ import annotations

import subprocess
import json
import logging
import tempfile
import os
from pathlib import Path
from typing import Optional

from cybersentinel.agents.base import BaseAgent
from cybersentinel.models.finding import Finding, Severity


logger = logging.getLogger(__name__)


class TrafficAnalysisAgent(BaseAgent):
    """Network traffic analysis via mitmproxy."""

    name = "traffic"
    description = "Network traffic analysis for security issues"

    # Security headers that should be present
    REQUIRED_HEADERS = {
        "Strict-Transport-Security": ("CWE-319", Severity.HIGH),
        "X-Content-Type-Options": ("CWE-693", Severity.MEDIUM),
        "X-Frame-Options": ("CWE-1021", Severity.MEDIUM),
        "Content-Security-Policy": ("CWE-79", Severity.MEDIUM),
        "X-XSS-Protection": ("CWE-79", Severity.LOW),
    }

    # Sensitive patterns in URLs/parameters
    SENSITIVE_PATTERNS = {
        "password": "CWE-798",
        "api_key": "CWE-798",
        "token": "CWE-798",
        "secret": "CWE-798",
        "authorization": "CWE-798",
        "credit_card": "CWE-200",
        "ssn": "CWE-200",
        "social_security": "CWE-200",
        "email": "CWE-200",
    }

    ADDON_SCRIPT = '''
import json
from mitmproxy import http

class TrafficLogger:
    def __init__(self, output_file):
        self.output_file = output_file
        self.issues = []

    def request(self, flow: http.HTTPFlow) -> None:
        """Analyze request."""
        request = flow.request

        # Check for sensitive data in URL
        url_lower = request.url.lower()
        for pattern in ["password", "api_key", "token", "secret"]:
            if pattern in url_lower:
                self.issues.append({
                    "type": "sensitive_in_url",
                    "url": request.url,
                    "pattern": pattern,
                })

        # Check for unencrypted transmission
        if request.scheme == "http" and not request.url.startswith("http://localhost"):
            self.issues.append({
                "type": "unencrypted_transmission",
                "url": request.url,
            })

    def response(self, flow: http.HTTPFlow) -> None:
        """Analyze response."""
        response = flow.response

        # Check security headers
        for header, _ in self.REQUIRED_HEADERS.items():
            if header not in response.headers:
                self.issues.append({
                    "type": "missing_header",
                    "header": header,
                    "url": flow.request.url,
                })

        # Check cookies
        if "Set-Cookie" in response.headers:
            cookies = response.headers.get_list("Set-Cookie")
            for cookie in cookies:
                cookie_lower = cookie.lower()
                if "secure" not in cookie_lower and flow.request.scheme == "https":
                    self.issues.append({
                        "type": "insecure_cookie",
                        "cookie": cookie.split("=")[0],
                        "url": flow.request.url,
                    })
                if "httponly" not in cookie_lower:
                    self.issues.append({
                        "type": "missing_httponly",
                        "cookie": cookie.split("=")[0],
                        "url": flow.request.url,
                    })

        # Check for mixed content
        content_type = response.headers.get("Content-Type", "")
        if flow.request.scheme == "https" and "text/html" in content_type:
            if response.content and b"http://" in response.content and b"https://" not in response.content:
                self.issues.append({
                    "type": "mixed_content",
                    "url": flow.request.url,
                })

    def __del__(self):
        """Write results on exit."""
        try:
            with open(self.output_file, "w") as f:
                json.dump(self.issues, f)
        except:
            pass

addons = [TrafficLogger("{output_file}")]
'''

    def analyze(self, target: str, context: dict) -> list[Finding]:
        """Analyze network traffic for security issues."""
        self.validate(target, f"Traffic analysis of {target}")
        self.log(f"Starting traffic analysis on {target}")

        findings: list[Finding] = []

        # Create temporary addon script
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as addon_file:
            addon_path = addon_file.name
            output_file = tempfile.mktemp(suffix=".json")
            addon_script = self.ADDON_SCRIPT.format(output_file=output_file)
            addon_file.write(addon_script)

        try:
            # Run mitmdump
            cmd = [
                "mitmdump",
                "-s", addon_path,
                "-w", output_file,
                "--set", "block_global=false",
            ]

            # If target is a URL, we need to configure proxy-based traffic capture
            # For now, just attempt to start mitmdump with the addon
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=120,
                )

                # Read results
                if os.path.exists(output_file):
                    with open(output_file, "r") as f:
                        issues = json.load(f)

                    findings = self._parse_traffic_issues(issues, target)

            except subprocess.TimeoutExpired:
                self.log("Traffic capture timeout")
            except FileNotFoundError:
                self.log("mitmdump not found")

        except Exception as e:
            self.log(f"Traffic analysis error: {str(e)[:200]}")

        finally:
            # Cleanup
            try:
                os.unlink(addon_path)
                if os.path.exists(output_file):
                    os.unlink(output_file)
            except:
                pass

        self.log(f"Traffic analysis complete: {len(findings)} findings")
        return findings

    def _parse_traffic_issues(self, issues: list[dict], target: str) -> list[Finding]:
        """Convert traffic issues to Findings."""
        findings = []

        for issue in issues:
            issue_type = issue.get("type", "")

            if issue_type == "insecure_cookie":
                finding = Finding(
                    title="Insecure Cookie — Missing Secure Flag",
                    severity=Severity.MEDIUM,
                    description=f"Cookie '{issue.get('cookie', '')}' is sent over HTTPS but lacks Secure flag.",
                    affected_component=issue.get("url", ""),
                    agent_source=self.name,
                    cwe_ids=["CWE-614"],
                    mitre_techniques=["T1557"],
                    remediation="Add 'Secure' flag to Set-Cookie header",
                )
                findings.append(finding)

            elif issue_type == "missing_httponly":
                finding = Finding(
                    title="Cookie — Missing HttpOnly Flag",
                    severity=Severity.MEDIUM,
                    description=f"Cookie '{issue.get('cookie', '')}' lacks HttpOnly flag, vulnerable to XSS.",
                    affected_component=issue.get("url", ""),
                    agent_source=self.name,
                    cwe_ids=["CWE-79"],
                    mitre_techniques=["T1189"],
                    remediation="Add 'HttpOnly' flag to Set-Cookie header",
                )
                findings.append(finding)

            elif issue_type == "missing_header":
                header = issue.get("header", "")
                cwe, sev = self.REQUIRED_HEADERS.get(header, ("CWE-693", Severity.LOW))
                finding = Finding(
                    title=f"Missing Security Header — {header}",
                    severity=sev,
                    description=f"Response from {issue.get('url', '')} is missing {header} header.",
                    affected_component=issue.get("url", ""),
                    agent_source=self.name,
                    cwe_ids=[cwe],
                    mitre_techniques=["T1189"],
                    remediation=f"Add '{header}' response header with appropriate value",
                )
                findings.append(finding)

            elif issue_type == "sensitive_in_url":
                pattern = issue.get("pattern", "")
                cwe = self.SENSITIVE_PATTERNS.get(pattern, "CWE-200")
                finding = Finding(
                    title=f"Sensitive Data in URL — {pattern.upper()}",
                    severity=Severity.HIGH,
                    description=f"Sensitive data pattern '{pattern}' found in URL.",
                    affected_component=issue.get("url", ""),
                    agent_source=self.name,
                    cwe_ids=[cwe],
                    mitre_techniques=["T1552"],
                    remediation="Use POST requests or headers for sensitive data. Never expose in URLs.",
                )
                findings.append(finding)

            elif issue_type == "unencrypted_transmission":
                finding = Finding(
                    title="Unencrypted Transmission",
                    severity=Severity.HIGH,
                    description=f"Data transmitted over HTTP without encryption.",
                    affected_component=issue.get("url", ""),
                    agent_source=self.name,
                    cwe_ids=["CWE-319"],
                    mitre_techniques=["T1557"],
                    remediation="Use HTTPS for all communications",
                )
                findings.append(finding)

            elif issue_type == "mixed_content":
                finding = Finding(
                    title="Mixed Content",
                    severity=Severity.MEDIUM,
                    description=f"HTTPS page contains unencrypted HTTP resources.",
                    affected_component=issue.get("url", ""),
                    agent_source=self.name,
                    cwe_ids=["CWE-295"],
                    mitre_techniques=["T1557"],
                    remediation="Ensure all resources loaded over HTTPS",
                )
                findings.append(finding)

        return findings
