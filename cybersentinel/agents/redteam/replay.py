"""Replay Agent — request replay and modification (Burp Repeater equivalent)."""

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
class PendingExploit:
    """A queued exploit pending human authorization."""

    original_request: str
    modified_request: str
    payload_description: str
    expected_outcome: str
    detection_probability: float  # 0.0-1.0
    exploit_id: str = ""
    is_authorized: bool = False


class ReplayAgent(BaseAgent):
    """Request replay and modification (Burp Repeater equivalent)."""

    name = "replay"
    description = "Generates modified requests for testing (Burp Repeater equivalent)"

    def __init__(self, session: Session):
        super().__init__(session)
        self.pending_exploits: list[PendingExploit] = []

    def analyze(self, target: str, context: dict) -> list[Finding]:
        """Generate modified requests from captured traffic.

        Args:
            target: Target identifier
            context: Dict with 'requests' key containing captured HTTP requests

        Returns:
            Findings with pending exploits queued for authorization
        """
        if not self.validate(target, "Request replay generation"):
            return []

        requests = context.get("requests", [])
        findings = context.get("findings", [])

        if not requests:
            self.log("No requests to replay")
            return []

        new_findings = []

        for i, request in enumerate(requests):
            # Create modified versions with payloads
            modified_requests = self._create_modified_requests(request, findings)

            for j, (modified_req, payload_desc, expected_outcome, detection_prob) in enumerate(modified_requests):
                exploit_id = f"replay_{i}_{j}"

                pending = PendingExploit(
                    original_request=request,
                    modified_request=modified_req,
                    payload_description=payload_desc,
                    expected_outcome=expected_outcome,
                    detection_probability=detection_prob,
                    exploit_id=exploit_id,
                )

                self.pending_exploits.append(pending)

                # Create finding for each pending exploit
                finding = Finding(
                    title=f"Pending Exploit: {payload_desc}",
                    severity=Severity.HIGH,
                    description=f"Modified request queued for testing. Requires authorization before execution.",
                    affected_component=target,
                    agent_source=self.name,
                    confidence="high",
                    evidence=self._format_exploit_evidence(pending),
                )

                new_findings.append(finding)
                self.log(f"Queued exploit: {exploit_id}")

        return new_findings

    def _create_modified_requests(
        self, original_request: str, findings: list[Finding]
    ) -> list[tuple[str, str, str, float]]:
        """Create modified requests from original request and findings."""
        modified_requests = []

        # Extract injection points from request
        injection_points = self._extract_injection_points(original_request)

        for param_name, value in injection_points:
            # SQL injection variants
            sqli_payloads = [
                ("' OR '1'='1' -- -", "SQL injection (OR-based)", "Boolean-based SQL injection"),
                ("' UNION SELECT NULL,version() -- -", "SQL injection (UNION-based)", "UNION-based SQLi"),
                ("' AND SLEEP(5) -- -", "SQL injection (time-based)", "Time-based blind SQLi"),
            ]

            for payload, desc, outcome in sqli_payloads:
                modified_req = original_request.replace(value, payload)
                modified_requests.append(
                    (modified_req, f"{param_name}: {desc}", outcome, 0.6)
                )

            # XSS variants
            xss_payloads = [
                ("<script>alert('XSS')</script>", "XSS (alert)", "JavaScript alert box displayed"),
                ("<img src=x onerror=alert('XSS')>", "XSS (event handler)", "Event handler executed"),
            ]

            for payload, desc, outcome in xss_payloads:
                modified_req = original_request.replace(value, payload)
                modified_requests.append(
                    (modified_req, f"{param_name}: {desc}", outcome, 0.5)
                )

        return modified_requests

    def _extract_injection_points(self, request: str) -> list[tuple[str, str]]:
        """Extract parameter injection points from a request."""
        injection_points = []

        # Parse POST data
        if "Content-Type: application/x-www-form-urlencoded" in request:
            body_start = request.find("\n\n")
            if body_start != -1:
                body = request[body_start + 2:]
                params = body.split("&")
                for param in params:
                    if "=" in param:
                        name, value = param.split("=", 1)
                        injection_points.append((name, value))

        # Parse GET query string
        if "?" in request:
            query_string = request[request.find("?") : request.find(" HTTP")]
            params = query_string[1:].split("&")
            for param in params:
                if "=" in param:
                    name, value = param.split("=", 1)
                    injection_points.append((name, value))

        return injection_points

    def _format_exploit_evidence(self, exploit: PendingExploit) -> str:
        """Format pending exploit as evidence."""
        evidence = f"=== Pending Exploit: {exploit.exploit_id} ===\n\n"

        evidence += f"Payload: {exploit.payload_description}\n"
        evidence += f"Expected Outcome: {exploit.expected_outcome}\n"
        evidence += f"Detection Probability: {exploit.detection_probability:.0%}\n\n"

        evidence += f"--- Original Request ---\n{exploit.original_request}\n\n"

        evidence += f"--- Modified Request ---\n{exploit.modified_request}\n\n"

        evidence += "STATUS: PENDING AUTHORIZATION\n"
        evidence += "Do NOT execute without explicit approval\n"

        return evidence

    def get_pending_exploits(self) -> list[PendingExploit]:
        """Get list of pending exploits."""
        return self.pending_exploits

    def authorize_exploit(self, exploit_id: str) -> bool:
        """Authorize a specific exploit for execution."""
        for exploit in self.pending_exploits:
            if exploit.exploit_id == exploit_id:
                exploit.is_authorized = True
                self.log(f"Authorized exploit: {exploit_id}")
                return True
        return False

    def revoke_exploit(self, exploit_id: str) -> bool:
        """Revoke authorization for an exploit."""
        for exploit in self.pending_exploits:
            if exploit.exploit_id == exploit_id:
                exploit.is_authorized = False
                self.log(f"Revoked exploit: {exploit_id}")
                return True
        return False

    def clear_pending_exploits(self) -> None:
        """Clear all pending exploits."""
        self.pending_exploits.clear()
        self.log("Cleared all pending exploits")
