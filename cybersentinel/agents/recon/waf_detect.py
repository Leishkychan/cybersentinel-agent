"""WAF Detection Agent — Layer 1 Reconnaissance.

Detects Web Application Firewalls by analyzing HTTP responses to benign and malicious requests.
"""

from __future__ import annotations

import re
import subprocess
from typing import TYPE_CHECKING

from cybersentinel.agents.base import BaseAgent
from cybersentinel.models.finding import Finding, Severity

if TYPE_CHECKING:
    from cybersentinel.models.session import Session


class WAFDetectAgent(BaseAgent):
    """Detects Web Application Firewalls through response analysis."""

    name = "waf_detect"
    description = "WAF detection — identifies web application firewalls"

    # Known WAF signatures in headers
    WAF_SIGNATURES = {
        "CF-RAY": ("Cloudflare", "Cloudflare WAF"),
        "X-Amz-Cf-Id": ("AWS CloudFront", "AWS CloudFront WAF"),
        "X-CDN-Powered-By": ("CDN-Powered", "Generic CDN WAF"),
        "X-Sucuri-ID": ("Sucuri", "Sucuri WAF"),
        "X-Sucuri-Cache": ("Sucuri", "Sucuri WAF"),
        "x-amzn-RequestId": ("AWS", "AWS WAF"),
        "X-Mod-Pagespeed": ("Google", "Google Mod PageSpeed"),
        "X-UA-Compatible": ("Microsoft", "Microsoft IIS"),
        "Akamai-Request-ID": ("Akamai", "Akamai WAF"),
        "X-Fortinet-FortiWAF": ("Fortinet", "Fortinet FortiWAF"),
        "X-Protected-By": ("Generic WAF", "Generic WAF Protection"),
    }

    # Response patterns that indicate WAF blocking
    BLOCK_PATTERNS = {
        "cloudflare": (
            r"(denied|blocked|error|challenge|captcha|ray=)",
            "Cloudflare appears to be blocking/challenging requests"
        ),
        "mod_security": (
            r"(403 Forbidden|ModSecurity|Action blocked)",
            "ModSecurity WAF detected — blocking malicious requests"
        ),
        "aws_waf": (
            r"(AWS WAF|AccessDenied|forbidden)",
            "AWS WAF detected — blocking requests"
        ),
        "fortinet": (
            r"(Fortinet|FortiWeb|block policy)",
            "Fortinet WAF detected — blocking requests"
        ),
        "imperva": (
            r"(Imperva|Incapsula|blocked)",
            "Imperva/Incapsula WAF detected — blocking requests"
        ),
    }

    def __init__(self, session: Session):
        super().__init__(session)

    def analyze(self, target: str, context: dict) -> list[Finding]:
        """Detect WAF on target URL.

        Args:
            target: The target URL or domain
            context: Additional context

        Returns:
            List of Finding objects indicating detected WAFs
        """
        self.validate(target, f"WAF detection on {target}")
        self.log(f"Starting WAF detection on {target}")

        findings: list[Finding] = []

        # Ensure URL is properly formatted
        url = target if target.startswith(('http://', 'https://')) else f"http://{target}"

        # Test 1: Benign request
        self.log("Testing with benign request")
        benign_response = self._make_request(url, benign=True)

        # Test 2: Malicious request
        self.log("Testing with potentially malicious request")
        malicious_response = self._make_request(url, benign=False)

        # Test 3: Check headers for WAF signatures
        self.log("Checking for WAF signatures in headers")
        waf_from_headers = self._check_waf_signatures(benign_response)

        # Analyze responses for WAF behavior
        if benign_response and malicious_response:
            waf_from_behavior = self._analyze_waf_behavior(
                url, benign_response, malicious_response
            )
            findings.extend(waf_from_behavior)

        findings.extend(waf_from_headers)

        self.log(f"WAF detection complete: {len(findings)} findings")
        return findings

    def _make_request(self, url: str, benign: bool = True) -> dict:
        """Make HTTP request with curl."""
        response = {
            "status": 0,
            "headers": {},
            "body": "",
        }

        try:
            if benign:
                # Clean request
                cmd = ["curl", "-s", "-i", url]
            else:
                # Add SQL injection payload to query string
                separator = "&" if "?" in url else "?"
                payload_url = f"{url}{separator}test=<script>alert(1)</script>"
                cmd = ["curl", "-s", "-i", payload_url]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
            )

            if result.returncode == 0:
                output = result.stdout
                lines = output.split('\n')

                # Parse status line
                if lines:
                    status_match = re.search(r'HTTP/[\d.]+\s+(\d+)', lines[0])
                    if status_match:
                        response["status"] = int(status_match.group(1))

                # Parse headers
                headers_end = 0
                for i, line in enumerate(lines):
                    if not line.strip():
                        headers_end = i
                        break
                    if ':' in line:
                        key, value = line.split(':', 1)
                        response["headers"][key.strip()] = value.strip()

                # Parse body
                if headers_end < len(lines):
                    response["body"] = '\n'.join(lines[headers_end + 1:])

        except FileNotFoundError:
            self.log("curl not found on system")
        except subprocess.TimeoutExpired:
            self.log("curl timed out")
        except Exception as e:
            self.log(f"curl error: {str(e)}")

        return response

    def _check_waf_signatures(self, response: dict) -> list[Finding]:
        """Check response headers for known WAF signatures."""
        findings = []
        headers = response.get("headers", {})

        for header_name, (waf_name, waf_type) in self.WAF_SIGNATURES.items():
            if header_name in headers or any(header_name.lower() == h.lower() for h in headers):
                findings.append(Finding(
                    title=f"WAF Detected: {waf_name}",
                    severity=Severity.INFO,
                    description=f"Web Application Firewall detected: {waf_type}. "
                                f"Header {header_name} indicates {waf_name} protection. "
                                f"This information helps understand defense mechanisms for scanning strategy.",
                    affected_component=response.get("url", ""),
                    agent_source=self.name,
                    mitre_tactics=["Reconnaissance"],
                    mitre_techniques=["T1595"],  # Active Scanning
                    evidence=f"Header: {header_name} = {headers[header_name]}",
                    confidence="high",
                ))

        return findings

    def _analyze_waf_behavior(self, url: str, benign: dict, malicious: dict) -> list[Finding]:
        """Analyze WAF behavior by comparing benign and malicious responses."""
        findings = []

        benign_status = benign.get("status", 0)
        malicious_status = malicious.get("status", 0)
        benign_body = benign.get("body", "")
        malicious_body = malicious.get("body", "")
        benign_headers = benign.get("headers", {})
        malicious_headers = malicious.get("headers", {})

        # Behavior 1: Status code difference
        if benign_status == 200 and malicious_status in [403, 406, 429]:
            findings.append(Finding(
                title=f"WAF Behavior Detected — Status Code Blocking",
                severity=Severity.INFO,
                description=f"WAF detected: Benign request returned {benign_status}, "
                           f"but request with potential XSS payload returned {malicious_status}. "
                           f"This indicates the WAF is filtering attack patterns.",
                affected_component=url,
                agent_source=self.name,
                mitre_tactics=["Reconnaissance"],
                mitre_techniques=["T1595"],
                evidence=f"Status code changed from {benign_status} to {malicious_status} with payload",
                confidence="high",
            ))

        # Behavior 2: Response body length significantly different
        benign_len = len(benign_body)
        malicious_len = len(malicious_body)

        if benign_len > 100 and malicious_len < benign_len / 2:
            findings.append(Finding(
                title=f"WAF Behavior Detected — Response Truncation",
                severity=Severity.INFO,
                description=f"WAF detected: Response was truncated when attack payload was included. "
                           f"Benign response: {benign_len} bytes, Malicious response: {malicious_len} bytes. "
                           f"This suggests WAF filtering is active.",
                affected_component=url,
                agent_source=self.name,
                mitre_tactics=["Reconnaissance"],
                mitre_techniques=["T1595"],
                evidence=f"Body length: {benign_len} -> {malicious_len}",
                confidence="high",
            ))

        # Behavior 3: Check for WAF error pages
        error_indicators = [
            "403 Forbidden",
            "406 Not Acceptable",
            "429 Too Many Requests",
            "blocked",
            "denied",
            "filtered",
            "suspicious",
            "malicious",
        ]

        malicious_lower = malicious_body.lower()
        for indicator in error_indicators:
            if indicator in malicious_lower and indicator not in benign_body.lower():
                findings.append(Finding(
                    title=f"WAF Response Pattern Detected",
                    severity=Severity.INFO,
                    description=f"WAF detected: Response contains '{indicator}' when attack payload is sent, "
                               f"but not in benign requests. This indicates active WAF filtering.",
                    affected_component=url,
                    agent_source=self.name,
                    mitre_tactics=["Reconnaissance"],
                    mitre_techniques=["T1595"],
                    evidence=f"Pattern '{indicator}' found in malicious response",
                    confidence="high",
                ))
                break

        # Behavior 4: Header differences
        malicious_header_keys = set(malicious_headers.keys())
        benign_header_keys = set(benign_headers.keys())
        new_headers = malicious_header_keys - benign_header_keys

        if new_headers:
            for header in new_headers:
                if "x-" in header.lower() or "cf-" in header.lower():
                    findings.append(Finding(
                        title=f"WAF Response Header: {header}",
                        severity=Severity.INFO,
                        description=f"New response header '{header}' present only in malicious response. "
                                   f"Value: {malicious_headers[header]}. This indicates WAF intervention.",
                        affected_component=url,
                        agent_source=self.name,
                        mitre_tactics=["Reconnaissance"],
                        mitre_techniques=["T1595"],
                        evidence=f"Header: {header}",
                        confidence="medium",
                    ))

        # Check for known WAF patterns in body
        for waf_pattern, (waf_desc, message) in self.BLOCK_PATTERNS.items():
            if re.search(waf_pattern, malicious_body, re.IGNORECASE):
                findings.append(Finding(
                    title=f"WAF Detected: {waf_desc}",
                    severity=Severity.INFO,
                    description=f"{message}. "
                               f"Attack patterns are being identified and blocked. "
                               f"This impacts scanning and exploitation strategy.",
                    affected_component=url,
                    agent_source=self.name,
                    mitre_tactics=["Reconnaissance"],
                    mitre_techniques=["T1595"],
                    evidence=f"Pattern '{waf_pattern}' found in response body",
                    confidence="high",
                ))

        return findings
