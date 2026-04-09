"""Nuclei Scanning Agent — Template-based Vulnerability Scanning.

Runs Nuclei with safe templates for:
- Misconfigurations
- Exposures
- CVE-based checks
- Default credentials
- SSL/TLS issues
- DNS issues
- Technology detection
- Token detection
- File discovery

HARDCODED blocked tags prevent dangerous operations:
- exploit, dos, brute-force, fuzzing, fuzz (cannot be overridden)
"""

from __future__ import annotations

import json
import subprocess
import logging
from typing import Optional

from cybersentinel.agents.base import BaseAgent
from cybersentinel.models.finding import Finding, Severity


logger = logging.getLogger(__name__)


class NucleiScanAgent(BaseAgent):
    """Template-based vulnerability scanning with Nuclei."""

    name = "nuclei"
    description = "Template-based vulnerability scanning (Nuclei)"

    # Safe tags that can be scanned
    SAFE_TAGS = [
        "misconfig",
        "exposure",
        "cve",
        "default-login",
        "ssl",
        "dns",
        "tech",
        "token",
        "file",
    ]

    # Blocked tags that CANNOT be overridden
    BLOCKED_TAGS = [
        "exploit",
        "dos",
        "brute-force",
        "fuzzing",
        "fuzz",
    ]

    # Nuclei severity to our Severity enum
    SEVERITY_MAP = {
        "info": Severity.INFO,
        "low": Severity.LOW,
        "medium": Severity.MEDIUM,
        "high": Severity.HIGH,
        "critical": Severity.CRITICAL,
    }

    # CWE mapping for common template IDs
    TEMPLATE_CWE_MAP = {
        "wordpress": "CWE-434",
        "cve": "CWE-200",  # Generic
        "misconfig": "CWE-16",
        "exposure": "CWE-200",
        "default-login": "CWE-522",
        "ssl": "CWE-295",
        "dns": "CWE-350",
        "cookie": "CWE-614",
        "header": "CWE-693",
        "token": "CWE-798",
        "file": "CWE-434",
    }

    def analyze(self, target: str, context: dict) -> list[Finding]:
        """Run Nuclei with safe templates."""
        self.validate(target, f"Nuclei scan of {target}")
        self.log(f"Starting Nuclei scan on {target}")

        findings: list[Finding] = []

        # Build tags list from context
        requested_tags = context.get("tags", self.SAFE_TAGS)
        if isinstance(requested_tags, str):
            requested_tags = [requested_tags]

        # Filter out blocked tags
        tags = [t for t in requested_tags if t not in self.BLOCKED_TAGS]
        if not tags:
            tags = self.SAFE_TAGS

        self.log(f"Using tags: {','.join(tags)}")

        try:
            findings = self._run_nuclei(target, tags)
        except Exception as e:
            self.log(f"Nuclei error: {str(e)[:200]}")

        self.log(f"Nuclei scan complete: {len(findings)} findings")
        return findings

    def _run_nuclei(self, target: str, tags: list[str]) -> list[Finding]:
        """Run Nuclei and parse JSON output."""
        findings = []

        try:
            cmd = [
                "nuclei",
                "-u", target,
                "-tags", ",".join(tags),
                "-exclude-tags", ",".join(self.BLOCKED_TAGS),
                "-json",
                "-rate-limit", "50",
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
            )

            # Parse JSON output (one object per line)
            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue

                try:
                    result_obj = json.loads(line)

                    severity = self.SEVERITY_MAP.get(
                        result_obj.get("info", {}).get("severity", "info").lower(),
                        Severity.INFO
                    )

                    # Extract CWE
                    template_id = result_obj.get("template_id", "")
                    cwe = None
                    for key, cwe_id in self.TEMPLATE_CWE_MAP.items():
                        if key in template_id.lower():
                            cwe = cwe_id
                            break
                    if not cwe:
                        cwe = "CWE-200"

                    # Extract CVE if present
                    cve_ids = []
                    template_info = result_obj.get("info", {})
                    if "cve" in template_info:
                        if isinstance(template_info["cve"], list):
                            cve_ids = template_info["cve"]
                        else:
                            cve_ids = [template_info["cve"]]

                    # Extract CVSS if present
                    cvss_score = None
                    if "cvss-score" in template_info:
                        try:
                            cvss_score = float(template_info["cvss-score"])
                        except (ValueError, TypeError):
                            pass

                    finding = Finding(
                        title=f"Nuclei: {result_obj.get('info', {}).get('name', 'Unknown')}",
                        severity=severity,
                        description=result_obj.get("info", {}).get("description", ""),
                        affected_component=result_obj.get("host", ""),
                        agent_source=self.name,
                        cve_ids=cve_ids,
                        cwe_ids=[cwe],
                        cvss_score=cvss_score,
                        evidence=result_obj.get("matched_at", ""),
                        mitre_techniques=self._map_attack(template_id),
                        remediation=result_obj.get("info", {}).get("remediation", ""),
                    )
                    findings.append(finding)

                except json.JSONDecodeError:
                    continue

        except subprocess.TimeoutExpired:
            self.log("Nuclei timeout")
        except FileNotFoundError:
            self.log("Nuclei not found")
        except Exception as e:
            self.log(f"Nuclei execution error: {str(e)[:200]}")

        return findings

    def _map_attack(self, template_id: str) -> list[str]:
        """Map template ID to MITRE ATT&CK techniques."""
        template_lower = template_id.lower()

        techniques = []

        if any(x in template_lower for x in ["cve", "exploit", "vuln"]):
            techniques.append("T1190")  # Exploit Public-Facing Application
        if any(x in template_lower for x in ["misconfig", "misconfigured"]):
            techniques.append("T1526")  # Exposure
        if any(x in template_lower for x in ["exposure", "exposed"]):
            techniques.append("T1526")  # Exposure
        if any(x in template_lower for x in ["default", "login", "credentials"]):
            techniques.append("T1078")  # Valid Accounts
        if any(x in template_lower for x in ["ssl", "tls", "certificate"]):
            techniques.append("T1557")  # Man-in-the-Middle
        if any(x in template_lower for x in ["dns"]):
            techniques.append("T1583")  # Acquire Infrastructure
        if any(x in template_lower for x in ["token", "secret", "api"]):
            techniques.append("T1552")  # Unsecured Credentials
        if any(x in template_lower for x in ["file", "backup", "config"]):
            techniques.append("T1083")  # File and Directory Discovery

        return techniques if techniques else ["T1190"]
