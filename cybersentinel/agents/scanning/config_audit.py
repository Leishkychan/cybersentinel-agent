"""Configuration Audit Agent — Enhanced Configuration Security Analysis.

Combines file-based config checking with live-host Nuclei scanning.
Covers: nginx, sshd, Docker, Terraform, AWS IAM, Kubernetes
"""

from __future__ import annotations

import subprocess
import json
import logging
from pathlib import Path
from typing import Optional

from cybersentinel.agents.base import BaseAgent
from cybersentinel.agents.config import (
    check_nginx,
    check_sshd,
    check_dockerfile,
    check_terraform,
    check_aws_iam,
)
from cybersentinel.models.finding import Finding, Severity


logger = logging.getLogger(__name__)


class ConfigAuditAgent(BaseAgent):
    """Enhanced configuration auditing with file and live-host checks."""

    name = "config_audit"
    description = "Configuration security audit (files + live hosts)"

    # Kubernetes config checks
    KUBE_CHECKS = {
        "rbac": "Role-Based Access Control not enforced",
        "network-policy": "Network policies not configured",
        "resource-limits": "Resource limits not defined",
        "security-context": "Security context not configured",
    }

    def analyze(self, target: str, context: dict) -> list[Finding]:
        """Audit configuration from file or live host."""
        self.validate(target, f"Configuration audit of {target}")
        self.log(f"Starting config audit on {target}")

        findings: list[Finding] = []

        # Check if target is a file or directory
        target_path = Path(target)

        if target_path.is_file():
            # File-based config checking
            findings = self._audit_config_file(target, context)
        elif target_path.is_dir():
            # Directory scan
            findings = self._audit_directory(target, context)
        else:
            # Assume it's a hostname/IP for live scanning
            findings = self._audit_live_host(target, context)

        self.log(f"Config audit complete: {len(findings)} findings")
        return findings

    def _audit_config_file(self, file_path: str, context: dict) -> list[Finding]:
        """Audit a single configuration file."""
        findings = []

        try:
            with open(file_path, "r") as f:
                config = f.read()
        except Exception as e:
            self.log(f"Error reading {file_path}: {str(e)[:100]}")
            return findings

        # Auto-detect config type
        config_type = self._detect_config_type(file_path, config)

        # Run appropriate checker
        if config_type == "nginx":
            issues = check_nginx(config)
        elif config_type == "sshd":
            issues = check_sshd(config)
        elif config_type == "dockerfile":
            issues = check_dockerfile(config)
        elif config_type == "terraform":
            issues = check_terraform(config)
        elif config_type == "aws_iam":
            issues = check_aws_iam(config)
        elif config_type == "kubernetes":
            issues = self._check_kubernetes(config)
        else:
            issues = []

        # Convert to Findings
        for issue in issues:
            finding = Finding(
                title=issue.get("title", ""),
                severity=issue.get("severity", Severity.MEDIUM),
                description=issue.get("detail", ""),
                affected_component=file_path,
                agent_source=self.name,
                cwe_ids=[issue.get("cwe", "CWE-16")],
                mitre_techniques=issue.get("mitre", []),
                remediation=issue.get("remediation", ""),
                evidence=f"Config check: {issue.get('cis_ref', 'N/A')}",
            )
            findings.append(finding)

        return findings

    def _audit_directory(self, dir_path: str, context: dict) -> list[Finding]:
        """Scan directory for configuration files."""
        findings = []
        dir_path = Path(dir_path)

        # Look for common config files
        config_patterns = {
            "**nginx.conf": "nginx",
            "**sshd_config": "sshd",
            "**/Dockerfile": "dockerfile",
            "**/*.tf": "terraform",
            "**/pom.xml": "java",
            "**/docker-compose.yml": "dockerfile",
            "**k8s-*.yaml": "kubernetes",
        }

        for pattern, config_type in config_patterns.items():
            for config_file in dir_path.glob(pattern):
                try:
                    file_findings = self._audit_config_file(str(config_file), {"config_type": config_type})
                    findings.extend(file_findings)
                except Exception as e:
                    self.log(f"Error scanning {config_file}: {str(e)[:100]}")

        return findings

    def _audit_live_host(self, host: str, context: dict) -> list[Finding]:
        """Run Nuclei misconfig checks on live host."""
        findings = []

        try:
            cmd = [
                "nuclei",
                "-u", f"http://{host}",
                "-tags", "misconfig",
                "-json",
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )

            # Parse Nuclei JSON output
            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue

                try:
                    result_obj = json.loads(line)

                    finding = Finding(
                        title=f"Misconfiguration: {result_obj.get('info', {}).get('name', '')}",
                        severity=self._nuclei_severity(result_obj.get("info", {}).get("severity", "info")),
                        description=result_obj.get("info", {}).get("description", ""),
                        affected_component=host,
                        agent_source=self.name,
                        cwe_ids=["CWE-16"],
                        mitre_techniques=["T1526"],
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
            self.log(f"Live host audit error: {str(e)[:200]}")

        return findings

    def _detect_config_type(self, file_path: str, content: str) -> Optional[str]:
        """Auto-detect config file type."""
        file_path_lower = file_path.lower()
        content_lower = content.lower()

        if "nginx" in file_path_lower or "server {" in content:
            return "nginx"
        elif "sshd" in file_path_lower or "PermitRootLogin" in content:
            return "sshd"
        elif "Dockerfile" in file_path or ("FROM " in content and "RUN " in content):
            return "dockerfile"
        elif file_path_lower.endswith(".tf") or "resource \"aws_" in content:
            return "terraform"
        elif "pom.xml" in file_path_lower or "<project>" in content:
            return "java"
        elif file_path_lower.endswith((".yaml", ".yml")) and "kind:" in content:
            return "kubernetes"
        elif "Statement" in content and "Effect" in content and "Action" in content:
            return "aws_iam"

        return None

    def _check_kubernetes(self, config: str) -> list[dict]:
        """Check Kubernetes manifest for security issues."""
        issues = []

        # Check for missing security context
        if "securityContext:" not in config:
            issues.append({
                "title": "Kubernetes — Missing Security Context",
                "detail": "Pod/container lacks securityContext configuration.",
                "remediation": "Add securityContext with runAsNonRoot, readOnlyRootFilesystem, etc.",
                "severity": Severity.HIGH,
                "cis_ref": "CIS K8s 5.1.1",
                "cwe": "CWE-250",
                "mitre": ["T1078"],
            })

        # Check for missing resource limits
        if "resources:" not in config or "limits:" not in config:
            issues.append({
                "title": "Kubernetes — Missing Resource Limits",
                "detail": "Pod lacks CPU and memory resource limits.",
                "remediation": "Add resources.limits for CPU and memory.",
                "severity": Severity.MEDIUM,
                "cis_ref": "CIS K8s 5.1.4",
                "cwe": "CWE-400",
                "mitre": ["T1499"],
            })

        # Check for privileged containers
        if "privileged: true" in config.lower():
            issues.append({
                "title": "Kubernetes — Privileged Container",
                "detail": "Container runs with privileged flag, bypassing security policies.",
                "remediation": "Set privileged: false. Use specific capabilities if needed.",
                "severity": Severity.CRITICAL,
                "cis_ref": "CIS K8s 5.2.1",
                "cwe": "CWE-250",
                "mitre": ["T1078"],
            })

        # Check for root user
        if "runAsNonRoot" not in config or "runAsUser: 0" in config:
            issues.append({
                "title": "Kubernetes — Running as Root",
                "detail": "Container runs as root user.",
                "remediation": "Set runAsNonRoot: true and specify runAsUser with non-zero value.",
                "severity": Severity.HIGH,
                "cis_ref": "CIS K8s 5.2.2",
                "cwe": "CWE-250",
                "mitre": ["T1078"],
            })

        # Check for read-only filesystem
        if "readOnlyRootFilesystem" not in config:
            issues.append({
                "title": "Kubernetes — Writable Root Filesystem",
                "detail": "Container root filesystem is writable.",
                "remediation": "Set readOnlyRootFilesystem: true.",
                "severity": Severity.MEDIUM,
                "cis_ref": "CIS K8s 5.2.3",
                "cwe": "CWE-434",
                "mitre": ["T1021"],
            })

        # Check for network policies
        if "networkPolicy" not in config and "NetworkPolicy" not in config:
            issues.append({
                "title": "Kubernetes — No Network Policies",
                "detail": "No network policies defined. All pods can communicate.",
                "remediation": "Create NetworkPolicy resources to restrict pod-to-pod traffic.",
                "severity": Severity.HIGH,
                "cis_ref": "CIS K8s 5.3.1",
                "cwe": "CWE-284",
                "mitre": ["T1021"],
            })

        return issues

    def _nuclei_severity(self, sev: str) -> Severity:
        """Convert Nuclei severity to our Severity enum."""
        sev_lower = sev.lower()
        if sev_lower == "critical":
            return Severity.CRITICAL
        elif sev_lower == "high":
            return Severity.HIGH
        elif sev_lower == "medium":
            return Severity.MEDIUM
        elif sev_lower == "low":
            return Severity.LOW
        else:
            return Severity.INFO
