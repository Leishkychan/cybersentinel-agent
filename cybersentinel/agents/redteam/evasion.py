"""Evasion Agent — WAF evasion and stealth assessment."""

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
class EvasionStrategy:
    """WAF evasion strategy."""

    waf_type: str
    evasion_techniques: list[str]
    payload_obfuscation: list[str]
    rate_limiting: str  # Recommended scan speed
    stealth_score: int  # 1-10, 10 is stealthiest


class EvasionAgent(BaseAgent):
    """WAF evasion and stealth assessment."""

    name = "evasion"
    description = "Provides WAF evasion strategies and stealth assessment"

    def __init__(self, session: Session):
        super().__init__(session)
        self.waf_database = self._initialize_waf_database()

    def analyze(self, target: str, context: dict) -> list[Finding]:
        """Analyze findings for WAF evasion opportunities.

        Args:
            target: Target identifier
            context: Dict with 'findings' and 'waf_type' keys

        Returns:
            Findings with WAF evasion strategies
        """
        if not self.validate(target, "WAF evasion assessment"):
            return []

        findings = context.get("findings", [])
        waf_type = context.get("waf_type", "unknown")

        if not findings:
            return []

        new_findings = []

        # Get evasion strategy for detected WAF
        if waf_type in self.waf_database:
            strategy = self.waf_database[waf_type]

            for finding in findings:
                # Only create evasion strategies for injection findings
                if not self._is_injectable_finding(finding):
                    continue

                evasion_finding = Finding(
                    title=f"WAF Evasion Strategy: {waf_type}",
                    severity=Severity.INFO,
                    description=self._format_evasion_description(strategy, finding),
                    affected_component=finding.affected_component,
                    agent_source=self.name,
                    confidence="medium",
                    evidence=self._format_evasion_evidence(strategy),
                )

                new_findings.append(evasion_finding)
                self.log(f"Generated evasion strategy for {waf_type}")

        return new_findings

    def _is_injectable_finding(self, finding: Finding) -> bool:
        """Check if a finding is injectable (vulnerable to attack)."""
        injectable_keywords = ["injection", "sqli", "xss", "command", "rce"]
        title_lower = finding.title.lower()
        return any(keyword in title_lower for keyword in injectable_keywords)

    def _initialize_waf_database(self) -> dict[str, EvasionStrategy]:
        """Initialize WAF evasion database."""
        return {
            "cloudflare": EvasionStrategy(
                waf_type="Cloudflare",
                evasion_techniques=[
                    "Use HTTP/2 instead of HTTP/1.1",
                    "Rotate user-agents frequently",
                    "Space requests across multiple seconds",
                    "Use charset obfuscation in payloads",
                    "Fragment SQL keywords with comments",
                ],
                payload_obfuscation=[
                    "SELECT/**/FROM",
                    "UNION/**/ALL/**/SELECT",
                    "' OR '1'='1",
                    "BASE64 encoded payloads",
                    "Case variation (sElEcT)",
                ],
                rate_limiting="1 request per 2-5 seconds",
                stealth_score=6,
            ),
            "aws_waf": EvasionStrategy(
                waf_type="AWS WAF",
                evasion_techniques=[
                    "Use double URL encoding",
                    "Append null bytes (%00)",
                    "Use tab characters instead of spaces",
                    "Fragment payloads across multiple parameters",
                    "Use hex encoding for SQL keywords",
                ],
                payload_obfuscation=[
                    "0x53454c454354 (SELECT in hex)",
                    "CONCAT(0x27,0x27) (quote concatenation)",
                    "Use mathematical operations: 1+1 instead of 2",
                    "CHAR() function for string building",
                ],
                rate_limiting="1 request per 3-5 seconds",
                stealth_score=7,
            ),
            "modsecurity": EvasionStrategy(
                waf_type="ModSecurity",
                evasion_techniques=[
                    "Use anomaly scoring to stay below threshold",
                    "Spread requests over longer timeframe",
                    "Use legitimate traffic patterns",
                    "Obfuscate SQL using comments and whitespace",
                    "Encode payloads in multiple layers",
                ],
                payload_obfuscation=[
                    "UNION/**/ALL/**/SELECT",
                    "<img src=x onerror=eval(atob('...'))>",
                    "String.fromCharCode() for XSS",
                    "INFORMATION_SCHEMA filtering",
                ],
                rate_limiting="1 request per 2-10 seconds",
                stealth_score=5,
            ),
            "akamai": EvasionStrategy(
                waf_type="Akamai",
                evasion_techniques=[
                    "Vary payload encoding with each request",
                    "Use legitimate browser identification",
                    "Spread requests across multiple source IPs",
                    "Use time delays between requests",
                    "Mimic normal user behavior patterns",
                ],
                payload_obfuscation=[
                    "Gzip compression of payloads",
                    "Mixed case SQL: SeLeCt",
                    "Mysql comment syntax: /**/",
                    "Percent encoding with variations: %20, %09, %0a",
                ],
                rate_limiting="1 request per 5-10 seconds",
                stealth_score=8,
            ),
            "imperva": EvasionStrategy(
                waf_type="Imperva",
                evasion_techniques=[
                    "Use traffic shaping to match legitimate patterns",
                    "Implement request pacing (slow scanning)",
                    "Use residential proxies",
                    "Rotate session IDs frequently",
                    "Obfuscate with encoding layers",
                ],
                payload_obfuscation=[
                    "Unicode encoding: %u0053%u0045%u004c",
                    "HTML entity encoding: &#x27; for '",
                    "Base64 wrapper: base64('payload')",
                    "Nested encoding: url -> base64 -> hex",
                ],
                rate_limiting="1 request per 5-15 seconds",
                stealth_score=9,
            ),
        }

    def _format_evasion_description(self, strategy: EvasionStrategy, finding: Finding) -> str:
        """Format evasion strategy description."""
        return (
            f"Evasion strategies for {strategy.waf_type} detected. "
            f"These techniques may help avoid detection while testing this vulnerability. "
            f"Stealth rating: {strategy.stealth_score}/10. "
            f"Recommended rate: {strategy.rate_limiting}."
        )

    def _format_evasion_evidence(self, strategy: EvasionStrategy) -> str:
        """Format evasion evidence."""
        evidence = f"=== {strategy.waf_type} Evasion Strategies ===\n\n"

        evidence += "Evasion Techniques:\n"
        for i, technique in enumerate(strategy.evasion_techniques, 1):
            evidence += f"  {i}. {technique}\n"

        evidence += "\nPayload Obfuscation Variants:\n"
        for variant in strategy.payload_obfuscation:
            evidence += f"  • {variant}\n"

        evidence += f"\nRecommended Scan Speed: {strategy.rate_limiting}\n"
        evidence += f"Stealth Score: {strategy.stealth_score}/10\n\n"

        evidence += "Best Practices:\n"
        evidence += "  • Alternate between different evasion techniques\n"
        evidence += "  • Monitor for 403/429 responses indicating detection\n"
        evidence += "  • Use proxies to vary source IP\n"
        evidence += "  • Rotate user-agents between requests\n"
        evidence += "  • Stop scanning if detection pattern emerges\n"

        return evidence

    def get_waf_strategies(self, waf_type: str) -> list[str]:
        """Get evasion strategies for a specific WAF."""
        if waf_type in self.waf_database:
            strategy = self.waf_database[waf_type]
            return strategy.evasion_techniques
        return []

    def get_stealth_score(self, waf_type: str) -> int:
        """Get stealth score for a WAF."""
        if waf_type in self.waf_database:
            return self.waf_database[waf_type].stealth_score
        return 0
