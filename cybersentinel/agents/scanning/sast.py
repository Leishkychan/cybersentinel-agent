"""SAST Agent — Static Application Security Testing.

Runs Semgrep, Bandit, and TruffleHog in parallel to detect:
- Code vulnerabilities
- Insecure patterns
- Hardcoded secrets

All tools are optional. Findings are deduplicated across tools.
"""

from __future__ import annotations

import json
import subprocess
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

from cybersentinel.agents.base import BaseAgent
from cybersentinel.models.finding import Finding, Severity


logger = logging.getLogger(__name__)


class SASTScanAgent(BaseAgent):
    """Runs Semgrep, Bandit, and TruffleHog for SAST analysis."""

    name = "sast"
    description = "Static application security testing (Semgrep, Bandit, TruffleHog)"

    # CWE mappings for common rule IDs
    SEMGREP_CWE_MAP = {
        "sql-injection": "CWE-89",
        "hardcoded": "CWE-798",
        "xss": "CWE-79",
        "path-traversal": "CWE-22",
        "command-injection": "CWE-78",
        "weak-crypto": "CWE-327",
        "insecure-deserialization": "CWE-502",
        "open-redirect": "CWE-601",
        "xxe": "CWE-611",
        "ldap-injection": "CWE-90",
    }

    BANDIT_CWE_MAP = {
        "B101": "CWE-391",  # assert_used
        "B102": "CWE-89",   # exec_used
        "B103": "CWE-78",   # set_bad_file_permissions
        "B104": "CWE-327",  # hardcoded_sql_string
        "B105": "CWE-327",  # hardcoded_password
        "B106": "CWE-798",  # hardcoded_password_string
        "B107": "CWE-327",  # hardcoded_password_default
        "B108": "CWE-327",  # hardcoded_password_funcarg
        "B110": "CWE-327",  # try_except_pass
        "B201": "CWE-327",  # flask_debug_true
        "B301": "CWE-502",  # pickle
        "B302": "CWE-611",  # marshal
        "B303": "CWE-502",  # md5
        "B304": "CWE-327",  # des
        "B305": "CWE-502",  # cipher
        "B306": "CWE-502",  # mktemp_q
        "B307": "CWE-502",  # eval
        "B308": "CWE-94",   # mark_safe
        "B309": "CWE-502",  # httpsconnection
        "B310": "CWE-502",  # urllib_urlopen
        "B311": "CWE-78",   # random
        "B312": "CWE-327",  # telnetlib
        "B313": "CWE-502",  # xmlrpc
        "B314": "CWE-502",  # xmlrpclib
        "B315": "CWE-502",  # xmlpickle
        "B316": "CWE-502",  # shelve
        "B317": "CWE-502",  # pickle_loads
        "B318": "CWE-611",  # xml_parse
        "B319": "CWE-502",  # yaml_load
        "B320": "CWE-502",  # unserialize
        "B321": "CWE-611",  # etree_parse
        "B322": "CWE-502",  # lxml_parse
        "B323": "CWE-327",  # unverified_context
        "B324": "CWE-295",  # hashlib_new
        "B325": "CWE-327",  # tempnam_q
        "B601": "CWE-434",  # paramiko_calls
        "B602": "CWE-78",   # subprocess_popen_with_shell_equals_true
        "B603": "CWE-78",   # subprocess_without_shell_equals_true
        "B604": "CWE-78",   # any_other_function_with_shell_equals_true
        "B605": "CWE-78",   # start_process_with_a_shell
        "B606": "CWE-427",  # start_process_with_no_shell
        "B607": "CWE-426",  # start_process_with_partial_path
        "B608": "CWE-89",   # hardcoded_sql_statements
        "B609": "CWE-426",  # wildcard_use_in_tmp_directory
        "B610": "CWE-502",  # django_raw_sql
        "B611": "CWE-78",   # sqlalchemy_execute
        "B701": "CWE-200",  # jinja2_autoescape_false
        "B702": "CWE-91",   # mako_templates
        "B703": "CWE-89",   # django_mark_safe
    }

    TRUFFLEHOG_SEVERITY = {
        "high": Severity.CRITICAL,
        "medium": Severity.HIGH,
        "low": Severity.MEDIUM,
    }

    def analyze(self, target: str, context: dict) -> list[Finding]:
        """Run SAST tools in parallel."""
        self.validate(target, f"SAST analysis of {target}")
        self.log(f"Starting SAST analysis on {target}")

        findings: list[Finding] = []
        target_path = Path(target)

        if not target_path.exists():
            self.log(f"Target path does not exist: {target}")
            return findings

        # Run all three tools in parallel
        with ThreadPoolExecutor(max_workers=3) as executor:
            semgrep_future = executor.submit(self._run_semgrep, str(target_path))
            bandit_future = executor.submit(self._run_bandit, str(target_path))
            trufflehog_future = executor.submit(self._run_trufflehog, str(target_path))

            semgrep_findings = semgrep_future.result()
            bandit_findings = bandit_future.result()
            trufflehog_findings = trufflehog_future.result()

        findings.extend(semgrep_findings)
        findings.extend(bandit_findings)
        findings.extend(trufflehog_findings)

        # Deduplicate findings (same file + line = same finding)
        deduplicated = self._deduplicate(findings)

        self.log(f"SAST analysis complete: {len(deduplicated)} findings (deduped from {len(findings)})")
        return deduplicated

    def _run_semgrep(self, target_dir: str) -> list[Finding]:
        """Run Semgrep and parse results."""
        findings = []
        try:
            cmd = [
                "semgrep",
                "scan",
                "--config", "auto",
                "--config", "p/owasp-top-ten",
                "--config", "p/security-audit",
                "--json",
                target_dir,
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.returncode not in [0, 1]:  # Semgrep returns 1 when findings exist
                self.log(f"Semgrep error: {result.stderr[:200]}")
                return findings

            data = json.loads(result.stdout)
            for result_obj in data.get("results", []):
                severity = self._semgrep_severity(result_obj.get("extra", {}).get("severity", "medium"))
                rule_id = result_obj.get("check_id", "")

                # Extract CWE from rule ID
                cwe = None
                for cwe_key, cwe_id in self.SEMGREP_CWE_MAP.items():
                    if cwe_key in rule_id.lower():
                        cwe = cwe_id
                        break

                finding = Finding(
                    title=f"Semgrep: {rule_id}",
                    severity=severity,
                    description=result_obj.get("extra", {}).get("message", ""),
                    affected_component=result_obj.get("path", ""),
                    agent_source=self.name,
                    cwe_ids=[cwe] if cwe else [],
                    evidence=f"Line {result_obj.get('start', {}).get('line', 'N/A')}",
                    mitre_techniques=self._map_attack_technique(rule_id),
                    remediation=result_obj.get("extra", {}).get("fix", ""),
                )
                findings.append(finding)

        except subprocess.TimeoutExpired:
            self.log("Semgrep timeout")
        except FileNotFoundError:
            self.log("Semgrep not found")
        except Exception as e:
            self.log(f"Semgrep error: {str(e)[:200]}")

        return findings

    def _run_bandit(self, target_dir: str) -> list[Finding]:
        """Run Bandit and parse results."""
        findings = []
        try:
            cmd = ["bandit", "-r", target_dir, "-f", "json"]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )

            data = json.loads(result.stdout)
            for result_obj in data.get("results", []):
                bandit_id = result_obj.get("test_id", "")
                cwe = self.BANDIT_CWE_MAP.get(bandit_id, "CWE-200")
                severity = self._bandit_severity(result_obj.get("severity", "MEDIUM"))

                finding = Finding(
                    title=f"Bandit: {result_obj.get('test', '')}",
                    severity=severity,
                    description=result_obj.get("issue_text", ""),
                    affected_component=result_obj.get("filename", ""),
                    agent_source=self.name,
                    cwe_ids=[cwe],
                    evidence=f"Line {result_obj.get('line_number', 'N/A')}",
                    mitre_techniques=self._map_attack_technique(bandit_id),
                )
                findings.append(finding)

        except subprocess.TimeoutExpired:
            self.log("Bandit timeout")
        except FileNotFoundError:
            self.log("Bandit not found")
        except Exception as e:
            self.log(f"Bandit error: {str(e)[:200]}")

        return findings

    def _run_trufflehog(self, target_dir: str) -> list[Finding]:
        """Run TruffleHog and parse results."""
        findings = []
        try:
            cmd = ["trufflehog", "filesystem", target_dir, "--json"]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )

            # TruffleHog outputs one JSON object per line
            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    result_obj = json.loads(line)

                    detection = result_obj.get("Detection", {})
                    detector_name = detection.get("DetectorName", "Secret")
                    verified = detection.get("Verified", False)
                    severity = Severity.CRITICAL if verified else Severity.HIGH

                    finding = Finding(
                        title=f"TruffleHog: {detector_name}",
                        severity=severity,
                        description=f"Potential hardcoded secret detected: {detector_name}",
                        affected_component=result_obj.get("SourceMetadata", {}).get("Data", {}).get("Filepath", ""),
                        agent_source=self.name,
                        cwe_ids=["CWE-798"],
                        evidence=f"Verified: {verified}",
                        mitre_techniques=["T1552.001"],  # Credentials in Files
                    )
                    findings.append(finding)
                except json.JSONDecodeError:
                    continue

        except subprocess.TimeoutExpired:
            self.log("TruffleHog timeout")
        except FileNotFoundError:
            self.log("TruffleHog not found")
        except Exception as e:
            self.log(f"TruffleHog error: {str(e)[:200]}")

        return findings

    def _deduplicate(self, findings: list[Finding]) -> list[Finding]:
        """Deduplicate findings by component + evidence."""
        seen = {}
        for finding in findings:
            key = (finding.affected_component, finding.evidence)
            if key not in seen:
                seen[key] = finding
            else:
                # Keep finding with higher severity
                existing = seen[key]
                severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
                if severity_order.index(finding.severity) < severity_order.index(existing.severity):
                    seen[key] = finding

        return list(seen.values())

    def _semgrep_severity(self, sev: str) -> Severity:
        """Map Semgrep severity to our Severity enum."""
        sev_lower = sev.lower()
        if sev_lower == "critical":
            return Severity.CRITICAL
        elif sev_lower == "error":
            return Severity.HIGH
        elif sev_lower == "warning":
            return Severity.MEDIUM
        else:
            return Severity.LOW

    def _bandit_severity(self, sev: str) -> Severity:
        """Map Bandit severity to our Severity enum."""
        if sev == "HIGH":
            return Severity.HIGH
        elif sev == "MEDIUM":
            return Severity.MEDIUM
        else:
            return Severity.LOW

    def _map_attack_technique(self, identifier: str) -> list[str]:
        """Map rule ID to MITRE ATT&CK techniques."""
        identifier_lower = identifier.lower()

        techniques = []

        if any(x in identifier_lower for x in ["sql", "injection", "command"]):
            techniques.append("T1190")  # Exploit Public-Facing Application
        if any(x in identifier_lower for x in ["hardcoded", "password", "secret", "key"]):
            techniques.append("T1552")  # Unsecured Credentials
        if any(x in identifier_lower for x in ["xss", "cross-site"]):
            techniques.append("T1189")  # Drive-by Compromise
        if any(x in identifier_lower for x in ["deserialization", "pickle", "yaml"]):
            techniques.append("T1190")  # Exploit Public-Facing Application
        if any(x in identifier_lower for x in ["xxe", "xml"]):
            techniques.append("T1190")  # Exploit Public-Facing Application

        return techniques
