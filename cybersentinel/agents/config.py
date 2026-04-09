"""Config Agent — Misconfiguration Detection.

Scope: Configuration files, IAM policies, firewall rules, cloud configs.
       Read-only analysis. Never applies changes or connects to cloud APIs.

Parses real configuration files and checks against security baselines.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from cybersentinel.agents.base import BaseAgent
from cybersentinel.models.finding import Finding, Severity


@dataclass
class ConfigRule:
    """A misconfiguration detection rule."""
    id: str
    title: str
    config_type: str  # nginx, sshd, dockerfile, terraform, aws_iam, etc.
    check: callable  # Function that takes config text, returns list of issues
    severity: Severity
    cwe: str
    cis_ref: str  # CIS benchmark reference
    description: str
    remediation: str
    mitre_techniques: list[str]


def check_nginx(config: str) -> list[dict]:
    """Check nginx config for security issues."""
    issues = []

    # autoindex on
    if re.search(r"autoindex\s+on", config, re.IGNORECASE):
        issues.append({
            "title": "Nginx — Directory Listing Enabled",
            "detail": "autoindex is set to 'on', exposing directory contents.",
            "remediation": "Set 'autoindex off;' in all server/location blocks.",
            "severity": Severity.MEDIUM,
            "cis_ref": "CIS Nginx 2.5.1",
            "cwe": "CWE-548",
            "mitre": ["T1083"],
        })

    # No HTTPS redirect (listening on 80 without redirect)
    if re.search(r"listen\s+80(?!\d)", config) and not re.search(r"return\s+301\s+https", config):
        issues.append({
            "title": "Nginx — HTTP Without HTTPS Redirect",
            "detail": "Server listens on port 80 without redirecting to HTTPS.",
            "remediation": "Add 'return 301 https://$host$request_uri;' to port 80 server block.",
            "severity": Severity.HIGH,
            "cis_ref": "CIS Nginx 4.1.1",
            "cwe": "CWE-319",
            "mitre": ["T1557"],
        })

    # Missing security headers
    headers = {
        "X-Frame-Options": ("CIS Nginx 4.3.1", Severity.MEDIUM, "CWE-1021"),
        "X-Content-Type-Options": ("CIS Nginx 4.3.2", Severity.MEDIUM, "CWE-693"),
        "X-XSS-Protection": ("CIS Nginx 4.3.3", Severity.LOW, "CWE-79"),
        "Content-Security-Policy": ("CIS Nginx 4.3.4", Severity.MEDIUM, "CWE-693"),
        "Strict-Transport-Security": ("CIS Nginx 4.3.5", Severity.HIGH, "CWE-319"),
    }
    for header, (cis, sev, cwe) in headers.items():
        if header.lower() not in config.lower():
            issues.append({
                "title": f"Nginx — Missing {header} Header",
                "detail": f"The {header} security header is not configured.",
                "remediation": f"Add 'add_header {header} <value>;' to server block.",
                "severity": sev,
                "cis_ref": cis,
                "cwe": cwe,
                "mitre": ["T1189"],
            })

    # server_tokens on (version disclosure)
    if "server_tokens off" not in config.lower():
        issues.append({
            "title": "Nginx — Server Version Disclosure",
            "detail": "server_tokens is not set to 'off'. Nginx version is exposed in response headers.",
            "remediation": "Add 'server_tokens off;' in http block.",
            "severity": Severity.LOW,
            "cis_ref": "CIS Nginx 2.5.2",
            "cwe": "CWE-200",
            "mitre": ["T1082"],
        })

    # PHP execution in upload directories
    if re.search(r"location.*upload.*\{[^}]*fastcgi_pass", config, re.DOTALL | re.IGNORECASE):
        issues.append({
            "title": "Nginx — PHP Execution in Upload Directory",
            "detail": "PHP execution is enabled in what appears to be an upload directory. Attackers can upload webshells.",
            "remediation": "Disable PHP execution in upload dirs: location ~ /uploads/.*\\.php$ { deny all; }",
            "severity": Severity.CRITICAL,
            "cis_ref": "OWASP",
            "cwe": "CWE-434",
            "mitre": ["T1505.003"],
        })

    # client_max_body_size not set or too large
    match = re.search(r"client_max_body_size\s+(\d+)([kmg]?)", config, re.IGNORECASE)
    if not match:
        issues.append({
            "title": "Nginx — No Upload Size Limit",
            "detail": "client_max_body_size is not configured. Default is 1MB but should be explicitly set.",
            "remediation": "Add 'client_max_body_size 10m;' (adjust to your needs) in server block.",
            "severity": Severity.LOW,
            "cis_ref": "CIS Nginx 5.2.1",
            "cwe": "CWE-400",
            "mitre": ["T1499"],
        })

    return issues


def check_sshd(config: str) -> list[dict]:
    """Check sshd_config for security issues."""
    issues = []

    checks = [
        (r"PermitRootLogin\s+yes", "SSH — Root Login Permitted",
         "Root SSH login is enabled. Compromising root = full system access.",
         "Set 'PermitRootLogin no' in sshd_config.",
         Severity.HIGH, "CIS 5.2.10", "CWE-250", ["T1078"]),

        (r"PasswordAuthentication\s+yes", "SSH — Password Authentication Enabled",
         "Password auth is enabled. Vulnerable to brute force attacks.",
         "Set 'PasswordAuthentication no'. Use key-based authentication only.",
         Severity.HIGH, "CIS 5.2.12", "CWE-307", ["T1110"]),

        (r"PermitEmptyPasswords\s+yes", "SSH — Empty Passwords Permitted",
         "Accounts with empty passwords can log in via SSH.",
         "Set 'PermitEmptyPasswords no'.",
         Severity.CRITICAL, "CIS 5.2.11", "CWE-258", ["T1078.001"]),

        (r"X11Forwarding\s+yes", "SSH — X11 Forwarding Enabled",
         "X11 forwarding is enabled. Can be exploited for X11 session hijacking.",
         "Set 'X11Forwarding no' unless explicitly needed.",
         Severity.LOW, "CIS 5.2.6", "CWE-829", ["T1021"]),

        (r"Protocol\s+1", "SSH — Protocol Version 1 Enabled",
         "SSHv1 has known cryptographic weaknesses and should never be used.",
         "Set 'Protocol 2' or remove the Protocol directive (v2 is default).",
         Severity.CRITICAL, "CIS 5.2.1", "CWE-327", ["T1557"]),
    ]

    for pattern, title, desc, remed, sev, cis, cwe, mitre in checks:
        if re.search(pattern, config, re.IGNORECASE):
            issues.append({
                "title": title, "detail": desc, "remediation": remed,
                "severity": sev, "cis_ref": cis, "cwe": cwe, "mitre": mitre,
            })

    # Check for missing MaxAuthTries
    if not re.search(r"MaxAuthTries\s+\d+", config):
        issues.append({
            "title": "SSH — No MaxAuthTries Limit",
            "detail": "MaxAuthTries not set. Default is 6, but should be explicitly configured to a lower value.",
            "remediation": "Add 'MaxAuthTries 3' to sshd_config.",
            "severity": Severity.MEDIUM, "cis_ref": "CIS 5.2.7",
            "cwe": "CWE-307", "mitre": ["T1110"],
        })

    # Check for missing LoginGraceTime
    if not re.search(r"LoginGraceTime\s+\d+", config):
        issues.append({
            "title": "SSH — No LoginGraceTime Set",
            "detail": "LoginGraceTime not configured. Should be set to limit authentication window.",
            "remediation": "Add 'LoginGraceTime 60' to sshd_config.",
            "severity": Severity.LOW, "cis_ref": "CIS 5.2.16",
            "cwe": "CWE-400", "mitre": ["T1499"],
        })

    return issues


def check_dockerfile(config: str) -> list[dict]:
    """Check Dockerfile for security issues."""
    issues = []

    # Running as root
    if not re.search(r"^USER\s+(?!root)", config, re.MULTILINE):
        issues.append({
            "title": "Docker — Container Runs as Root",
            "detail": "No non-root USER directive found. Container processes run as root by default.",
            "remediation": "Add 'USER nonroot' after installing dependencies. Create the user with 'RUN adduser --disabled-password nonroot'.",
            "severity": Severity.HIGH, "cis_ref": "CIS Docker 4.1",
            "cwe": "CWE-250", "mitre": ["T1078"],
        })

    # Using latest tag
    if re.search(r"^FROM\s+\S+:latest", config, re.MULTILINE):
        issues.append({
            "title": "Docker — Using 'latest' Tag",
            "detail": "Base image uses ':latest' tag. This is non-deterministic and may pull vulnerable versions.",
            "remediation": "Pin to a specific version tag (e.g., 'python:3.11-slim').",
            "severity": Severity.MEDIUM, "cis_ref": "CIS Docker 4.2",
            "cwe": "CWE-1104", "mitre": ["T1195.002"],
        })

    # COPY with wildcard (may include secrets)
    if re.search(r"^COPY\s+\.\s+", config, re.MULTILINE):
        issues.append({
            "title": "Docker — COPY . (Entire Context)",
            "detail": "Copies entire build context into image. May include .env, .git, secrets, or other sensitive files.",
            "remediation": "Use specific COPY paths and a .dockerignore file. Never copy the entire context.",
            "severity": Severity.MEDIUM, "cis_ref": "CIS Docker 4.10",
            "cwe": "CWE-200", "mitre": ["T1552"],
        })

    # ADD instead of COPY (ADD has tar extraction and URL fetching)
    if re.search(r"^ADD\s+", config, re.MULTILINE):
        issues.append({
            "title": "Docker — Using ADD Instead of COPY",
            "detail": "ADD has implicit tar extraction and URL fetching capabilities. Use COPY for transparency.",
            "remediation": "Replace ADD with COPY unless you specifically need tar extraction.",
            "severity": Severity.LOW, "cis_ref": "CIS Docker 4.9",
            "cwe": "CWE-829", "mitre": ["T1195.002"],
        })

    # Secrets in ENV
    if re.search(r"^ENV\s+.*(?:PASSWORD|SECRET|KEY|TOKEN|API_KEY)\s*=", config, re.MULTILINE | re.IGNORECASE):
        issues.append({
            "title": "Docker — Secrets in ENV Directive",
            "detail": "Environment variable containing secrets is baked into the image layer. Anyone with image access can extract it.",
            "remediation": "Use Docker secrets, mount secret files at runtime, or use --secret flag in BuildKit.",
            "severity": Severity.CRITICAL, "cis_ref": "CIS Docker 4.10",
            "cwe": "CWE-798", "mitre": ["T1552.001"],
        })

    return issues


def check_terraform(config: str) -> list[dict]:
    """Check Terraform files for security issues."""
    issues = []

    # S3 bucket without encryption
    if re.search(r'resource\s+"aws_s3_bucket"', config) and not re.search(r"server_side_encryption", config):
        issues.append({
            "title": "Terraform — S3 Bucket Without Encryption",
            "detail": "S3 bucket created without server-side encryption configured.",
            "remediation": "Add aws_s3_bucket_server_side_encryption_configuration resource with AES256 or aws:kms.",
            "severity": Severity.HIGH, "cis_ref": "CIS AWS 2.1.1",
            "cwe": "CWE-311", "mitre": ["T1530"],
        })

    # Security group with 0.0.0.0/0 ingress
    if re.search(r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]', config):
        issues.append({
            "title": "Terraform — Security Group Open to World",
            "detail": "Ingress rule allows traffic from 0.0.0.0/0 (entire internet).",
            "remediation": "Restrict cidr_blocks to specific IP ranges. Use VPN or bastion for administrative access.",
            "severity": Severity.HIGH, "cis_ref": "CIS AWS 5.2",
            "cwe": "CWE-284", "mitre": ["T1190"],
        })

    # Hardcoded credentials in provider
    if re.search(r'(?:access_key|secret_key)\s*=\s*"[^"]{10,}"', config):
        issues.append({
            "title": "Terraform — Hardcoded AWS Credentials",
            "detail": "AWS access or secret key hardcoded in Terraform. Anyone with repo access has these credentials.",
            "remediation": "Use environment variables, AWS profiles, or IAM roles. Never hardcode credentials in Terraform.",
            "severity": Severity.CRITICAL, "cis_ref": "CIS AWS 1.14",
            "cwe": "CWE-798", "mitre": ["T1552.001"],
        })

    # RDS without encryption
    if re.search(r'resource\s+"aws_db_instance"', config) and not re.search(r"storage_encrypted\s*=\s*true", config):
        issues.append({
            "title": "Terraform — RDS Without Encryption at Rest",
            "detail": "RDS instance created without storage encryption.",
            "remediation": "Add 'storage_encrypted = true' to the aws_db_instance resource.",
            "severity": Severity.HIGH, "cis_ref": "CIS AWS 2.3.1",
            "cwe": "CWE-311", "mitre": ["T1530"],
        })

    # Public subnets for databases
    if re.search(r'resource\s+"aws_db_instance"', config) and re.search(r"publicly_accessible\s*=\s*true", config):
        issues.append({
            "title": "Terraform — RDS Publicly Accessible",
            "detail": "RDS instance is set to publicly accessible. Databases should never be directly internet-facing.",
            "remediation": "Set 'publicly_accessible = false'. Access via VPN, bastion, or private subnets only.",
            "severity": Severity.CRITICAL, "cis_ref": "CIS AWS 2.3.2",
            "cwe": "CWE-284", "mitre": ["T1190"],
        })

    return issues


def check_aws_iam(config: str) -> list[dict]:
    """Check AWS IAM policy JSON for security issues."""
    issues = []

    try:
        policy = json.loads(config)
        statements = policy.get("Statement", [])

        for stmt in statements:
            effect = stmt.get("Effect", "")
            action = stmt.get("Action", "")
            resource = stmt.get("Resource", "")

            # Wildcard admin policy
            if effect == "Allow" and action == "*" and resource == "*":
                issues.append({
                    "title": "AWS IAM — Full Admin Access (Action: *, Resource: *)",
                    "detail": "Policy grants unrestricted access to all AWS services and resources. This is the equivalent of root access.",
                    "remediation": "Apply least-privilege. Scope actions to specific services and resources needed.",
                    "severity": Severity.CRITICAL, "cis_ref": "CIS AWS 1.16",
                    "cwe": "CWE-250", "mitre": ["T1078.004"],
                })

            # s3:* on all buckets
            if effect == "Allow" and isinstance(action, str) and "s3:*" in action:
                issues.append({
                    "title": "AWS IAM — Full S3 Access",
                    "detail": "Policy grants full S3 access. This includes ability to read, write, and delete all S3 data.",
                    "remediation": "Scope to specific S3 actions (s3:GetObject, s3:PutObject) and specific bucket ARNs.",
                    "severity": Severity.HIGH, "cis_ref": "CIS AWS 1.16",
                    "cwe": "CWE-250", "mitre": ["T1530"],
                })

            # No condition on sensitive actions
            sensitive_actions = ["iam:*", "sts:AssumeRole", "kms:*", "lambda:*"]
            if effect == "Allow" and "Condition" not in stmt:
                if isinstance(action, str) and any(a in action for a in sensitive_actions):
                    issues.append({
                        "title": f"AWS IAM — Sensitive Action Without Condition",
                        "detail": f"Policy allows '{action}' without any conditions (MFA, IP restriction, etc.).",
                        "remediation": "Add conditions: require MFA (aws:MultiFactorAuthPresent), restrict source IP, or require specific tags.",
                        "severity": Severity.HIGH, "cis_ref": "CIS AWS 1.14",
                        "cwe": "CWE-284", "mitre": ["T1078.004"],
                    })
    except (json.JSONDecodeError, AttributeError, TypeError):
        pass

    return issues


# Map config types to their checker functions
CONFIG_CHECKERS = {
    "nginx": check_nginx,
    "sshd": check_sshd,
    "dockerfile": check_dockerfile,
    "terraform": check_terraform,
    "aws_iam": check_aws_iam,
}


class ConfigAgent(BaseAgent):
    """Analyzes configuration files for security misconfigurations."""

    name = "config"
    description = "Misconfiguration detection — config file analysis"

    def analyze(self, target: str, context: dict) -> list[Finding]:
        """Analyze configuration for security issues."""
        self.validate(target, f"Configuration analysis of {target}")
        self.log(f"Starting config analysis on {target}")

        findings: list[Finding] = []
        config = context.get("config", "")
        config_type = context.get("config_type", "").lower()

        if not config.strip():
            self.log("No config content provided")
            return findings

        # Auto-detect config type if not specified
        if not config_type:
            if "server {" in config or "location" in config or "nginx" in config.lower():
                config_type = "nginx"
            elif "PermitRootLogin" in config or "PasswordAuthentication" in config:
                config_type = "sshd"
            elif "FROM " in config and ("RUN " in config or "CMD " in config):
                config_type = "dockerfile"
            elif "resource " in config and ("aws_" in config or "azurerm_" in config):
                config_type = "terraform"
            elif '"Statement"' in config and '"Effect"' in config:
                config_type = "aws_iam"

        checker = CONFIG_CHECKERS.get(config_type)
        if not checker:
            self.log(f"No checker for config type: {config_type}")
            return findings

        issues = checker(config)

        for issue in issues:
            findings.append(Finding(
                title=issue["title"],
                severity=issue["severity"],
                description=issue["detail"],
                affected_component=target,
                agent_source=self.name,
                cwe_ids=[issue["cwe"]],
                mitre_techniques=issue.get("mitre", []),
                remediation=issue["remediation"],
                evidence=f"Config check: {issue.get('cis_ref', 'N/A')}",
            ))

        self.log(f"Config analysis complete: {len(findings)} findings")
        return findings
