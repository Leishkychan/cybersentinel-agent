"""Dependency Scanning Agent — Multi-ecosystem dependency vulnerability scanning.

Supports:
- pip (requirements.txt) → pip-audit
- npm (package.json) → npm audit
- Go (go.mod) → govulncheck
- Ruby (Gemfile.lock) → bundler-audit
- Java (pom.xml) → OWASP dependency-check

All applicable scanners run in parallel.
"""

from __future__ import annotations

import json
import subprocess
import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Optional

from cybersentinel.agents.base import BaseAgent
from cybersentinel.models.finding import Finding, Severity


logger = logging.getLogger(__name__)


class DependencyScanAgent(BaseAgent):
    """Scans dependencies across multiple ecosystems for vulnerabilities."""

    name = "dependency"
    description = "Multi-ecosystem dependency vulnerability scanning"

    # CISA KEV list (simplified — in production, fetch from CISA)
    CISA_KEV_CVES = {
        "CVE-2021-44228",  # Log4Shell
        "CVE-2021-3129",   # Laravel
        "CVE-2021-21224",  # Chrome
        "CVE-2021-20090",  # AWS CloudFormation
        "CVE-2021-22945",  # curl
        "CVE-2021-22946",  # curl
        "CVE-2021-22947",  # curl
        "CVE-2021-3156",   # sudo
        "CVE-2021-3129",   # Composer
        "CVE-2021-26855",  # Microsoft Exchange
    }

    def analyze(self, target: str, context: dict) -> list[Finding]:
        """Auto-detect and run applicable dependency scanners."""
        self.validate(target, f"Dependency scan of {target}")
        self.log(f"Starting dependency scan on {target}")

        findings: list[Finding] = []
        target_path = Path(target)

        if not target_path.exists():
            self.log(f"Target path does not exist: {target}")
            return findings

        # Detect which manifests exist
        manifest_checks = {
            "pip": target_path / "requirements.txt",
            "npm": target_path / "package.json",
            "go": target_path / "go.mod",
            "ruby": target_path / "Gemfile.lock",
            "java": target_path / "pom.xml",
        }

        # Run applicable scanners in parallel
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {}

            if manifest_checks["pip"].exists():
                futures["pip"] = executor.submit(self._scan_pip, str(manifest_checks["pip"]))

            if manifest_checks["npm"].exists():
                futures["npm"] = executor.submit(self._scan_npm, str(target_path))

            if manifest_checks["go"].exists():
                futures["go"] = executor.submit(self._scan_go, str(target_path))

            if manifest_checks["ruby"].exists():
                futures["ruby"] = executor.submit(self._scan_ruby)

            if manifest_checks["java"].exists():
                futures["java"] = executor.submit(self._scan_java, str(target_path))

            for scanner, future in futures.items():
                try:
                    results = future.result()
                    findings.extend(results)
                except Exception as e:
                    self.log(f"{scanner} scanner error: {str(e)[:100]}")

        self.log(f"Dependency scan complete: {len(findings)} findings")
        return findings

    def _scan_pip(self, requirements_file: str) -> list[Finding]:
        """Run pip-audit on requirements.txt."""
        findings = []
        try:
            cmd = ["pip-audit", "-r", requirements_file, "--format", "json"]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )

            data = json.loads(result.stdout)
            for vuln in data.get("vulnerabilities", []):
                cve_ids = vuln.get("cve", [])
                if isinstance(cve_ids, str):
                    cve_ids = [cve_ids]

                severity = self._cvss_to_severity(vuln.get("cvss_score"))
                is_cisa_kev = any(cve in self.CISA_KEV_CVES for cve in cve_ids)

                finding = Finding(
                    title=f"Python: {vuln.get('name', '')} {vuln.get('version', '')}",
                    severity=severity,
                    description=vuln.get("description", ""),
                    affected_component=f"Python: {vuln.get('name', '')}",
                    agent_source=self.name,
                    cve_ids=cve_ids,
                    cvss_score=vuln.get("cvss_score"),
                    cisa_kev=is_cisa_kev,
                    mitre_techniques=["T1195.001"],  # Supply Chain Compromise
                    evidence=f"Version: {vuln.get('version', 'N/A')}",
                    remediation=f"Update {vuln.get('name', '')} to a patched version",
                )
                findings.append(finding)

        except subprocess.TimeoutExpired:
            self.log("pip-audit timeout")
        except FileNotFoundError:
            self.log("pip-audit not found")
        except Exception as e:
            self.log(f"pip-audit error: {str(e)[:200]}")

        return findings

    def _scan_npm(self, target_dir: str) -> list[Finding]:
        """Run npm audit in target directory."""
        findings = []
        try:
            cmd = ["npm", "audit", "--json"]
            result = subprocess.run(
                cmd,
                cwd=target_dir,
                capture_output=True,
                text=True,
                timeout=120,
            )

            data = json.loads(result.stdout)
            for name, vuln in data.get("vulnerabilities", {}).items():
                cve_id = vuln.get("cves", [])
                if isinstance(cve_id, str):
                    cve_id = [cve_id]

                severity = self._npm_severity(vuln.get("severity", "low"))
                is_cisa_kev = any(cve in self.CISA_KEV_CVES for cve in cve_id)

                finding = Finding(
                    title=f"NPM: {name}",
                    severity=severity,
                    description=vuln.get("title", ""),
                    affected_component=f"NPM: {name}",
                    agent_source=self.name,
                    cve_ids=cve_id,
                    cisa_kev=is_cisa_kev,
                    mitre_techniques=["T1195.001"],  # Supply Chain Compromise
                    evidence=f"Version: {vuln.get('via', [{}])[0].get('version', 'N/A')}",
                    remediation=vuln.get("recommendation", "Update to a patched version"),
                )
                findings.append(finding)

        except subprocess.TimeoutExpired:
            self.log("npm audit timeout")
        except FileNotFoundError:
            self.log("npm not found")
        except Exception as e:
            self.log(f"npm audit error: {str(e)[:200]}")

        return findings

    def _scan_go(self, target_dir: str) -> list[Finding]:
        """Run govulncheck in target directory."""
        findings = []
        try:
            cmd = ["govulncheck", "./..."]
            result = subprocess.run(
                cmd,
                cwd=target_dir,
                capture_output=True,
                text=True,
                timeout=120,
            )

            # govulncheck output is text-based; parse for CVE mentions
            output = result.stdout
            lines = output.split("\n")

            for line in lines:
                if "CVE-" in line or "GO-" in line:
                    # Extract CVE ID
                    cve_match = None
                    for word in line.split():
                        if word.startswith("CVE-"):
                            cve_match = word
                            break

                    if cve_match:
                        finding = Finding(
                            title=f"Go: {cve_match}",
                            severity=Severity.HIGH,
                            description=line,
                            affected_component="Go dependencies",
                            agent_source=self.name,
                            cve_ids=[cve_match] if cve_match else [],
                            mitre_techniques=["T1195.001"],  # Supply Chain Compromise
                            remediation="Run 'go get -u' to update dependencies",
                        )
                        findings.append(finding)

        except subprocess.TimeoutExpired:
            self.log("govulncheck timeout")
        except FileNotFoundError:
            self.log("govulncheck not found")
        except Exception as e:
            self.log(f"govulncheck error: {str(e)[:200]}")

        return findings

    def _scan_ruby(self) -> list[Finding]:
        """Run bundler-audit."""
        findings = []
        try:
            cmd = ["bundler-audit", "check", "--format", "json"]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )

            data = json.loads(result.stdout)
            for vuln in data.get("vulnerabilities", []):
                cve_ids = [vuln.get("cve", "")] if vuln.get("cve") else []
                severity = self._cvss_to_severity(vuln.get("cvss_score"))
                is_cisa_kev = any(cve in self.CISA_KEV_CVES for cve in cve_ids)

                finding = Finding(
                    title=f"Ruby: {vuln.get('gem', '')}",
                    severity=severity,
                    description=vuln.get("title", ""),
                    affected_component=f"Ruby: {vuln.get('gem', '')}",
                    agent_source=self.name,
                    cve_ids=cve_ids,
                    cvss_score=vuln.get("cvss_score"),
                    cisa_kev=is_cisa_kev,
                    mitre_techniques=["T1195.001"],  # Supply Chain Compromise
                    evidence=f"Version: {vuln.get('vulnerable_versions', ['N/A'])[0]}",
                    remediation=vuln.get("patched_versions", ["Update to a patched version"])[0],
                )
                findings.append(finding)

        except subprocess.TimeoutExpired:
            self.log("bundler-audit timeout")
        except FileNotFoundError:
            self.log("bundler-audit not found")
        except Exception as e:
            self.log(f"bundler-audit error: {str(e)[:200]}")

        return findings

    def _scan_java(self, target_dir: str) -> list[Finding]:
        """Run OWASP dependency-check CLI."""
        findings = []
        try:
            cmd = [
                "dependency-check.sh",
                "--project", "JavaProject",
                "--scan", target_dir,
                "--format", "JSON",
                "--out", "/tmp/dc-report.json",
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )

            # Read generated report
            try:
                with open("/tmp/dc-report.json", "r") as f:
                    data = json.load(f)

                for report_schema in data.get("reportSchema", {}).get("dependencies", []):
                    for vuln in report_schema.get("vulnerabilities", []):
                        cve_ids = [vuln.get("name", "")]
                        severity = self._owasp_severity(vuln.get("severity", "Unknown"))
                        is_cisa_kev = any(cve in self.CISA_KEV_CVES for cve in cve_ids)

                        finding = Finding(
                            title=f"Java: {vuln.get('name', 'Unknown Vulnerability')}",
                            severity=severity,
                            description=vuln.get("description", ""),
                            affected_component=f"Java: {report_schema.get('fileName', 'unknown')}",
                            agent_source=self.name,
                            cve_ids=cve_ids,
                            cvss_score=vuln.get("cvssScore"),
                            cisa_kev=is_cisa_kev,
                            mitre_techniques=["T1195.001"],  # Supply Chain Compromise
                            remediation="Update the affected dependency to a patched version",
                        )
                        findings.append(finding)
            except FileNotFoundError:
                pass

        except subprocess.TimeoutExpired:
            self.log("dependency-check timeout")
        except FileNotFoundError:
            self.log("dependency-check not found")
        except Exception as e:
            self.log(f"dependency-check error: {str(e)[:200]}")

        return findings

    def _cvss_to_severity(self, cvss_score: Optional[float]) -> Severity:
        """Convert CVSS score to Severity."""
        if not cvss_score:
            return Severity.MEDIUM

        if cvss_score >= 9.0:
            return Severity.CRITICAL
        elif cvss_score >= 7.0:
            return Severity.HIGH
        elif cvss_score >= 4.0:
            return Severity.MEDIUM
        else:
            return Severity.LOW

    def _npm_severity(self, sev: str) -> Severity:
        """Map npm severity to our Severity enum."""
        sev_lower = sev.lower()
        if sev_lower == "critical":
            return Severity.CRITICAL
        elif sev_lower == "high":
            return Severity.HIGH
        elif sev_lower == "moderate":
            return Severity.MEDIUM
        else:
            return Severity.LOW

    def _owasp_severity(self, sev: str) -> Severity:
        """Map OWASP severity to our Severity enum."""
        sev_lower = sev.lower()
        if sev_lower in ["critical", "high"]:
            return Severity.CRITICAL
        elif sev_lower == "medium":
            return Severity.HIGH
        elif sev_lower == "low":
            return Severity.MEDIUM
        else:
            return Severity.LOW
