"""OSINT Agent — Layer 1 Reconnaissance.

Queries public APIs (Shodan, Censys, VirusTotal) for external intelligence.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Optional

from cybersentinel.agents.base import BaseAgent
from cybersentinel.models.finding import Finding, Severity

if TYPE_CHECKING:
    from cybersentinel.models.session import Session

try:
    import requests
except ImportError:
    requests = None


class OSINTAgent(BaseAgent):
    """Gathers OSINT from public APIs and databases."""

    name = "osint"
    description = "OSINT intelligence — queries Shodan, Censys, VirusTotal APIs"

    def __init__(self, session: Session):
        super().__init__(session)
        self.api_keys = self._load_api_keys()

    def analyze(self, target: str, context: dict) -> list[Finding]:
        """Gather OSINT intelligence on target.

        Args:
            target: The target IP or domain
            context: Additional context

        Returns:
            List of Finding objects from OSINT sources
        """
        self.validate(target, f"OSINT intelligence gathering on {target}")
        self.log(f"Starting OSINT gathering on {target}")

        findings: list[Finding] = []

        if not requests:
            self.log("requests library not available, skipping OSINT")
            return findings

        # Try Shodan if IP
        if self._is_ip(target):
            shodan_findings = self._query_shodan(target)
            findings.extend(shodan_findings)

            # Censys for IP
            censys_findings = self._query_censys_ip(target)
            findings.extend(censys_findings)

        # Try VirusTotal for domain or IP
        vt_findings = self._query_virustotal(target)
        findings.extend(vt_findings)

        self.log(f"OSINT gathering complete: {len(findings)} findings")
        return findings

    def _load_api_keys(self) -> dict:
        """Load API keys from session/config."""
        # In a real implementation, these would come from secure config
        # For now, we check environment and session context
        keys = {}

        # Try to get from session context
        if hasattr(self.session, 'config'):
            config = self.session.config
            keys['shodan'] = config.get('shodan_api_key', '')
            keys['censys_id'] = config.get('censys_id', '')
            keys['censys_secret'] = config.get('censys_secret', '')
            keys['virustotal'] = config.get('virustotal_api_key', '')

        return keys

    def _is_ip(self, target: str) -> bool:
        """Check if target is an IP address."""
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return bool(re.match(ip_pattern, target))

    def _query_shodan(self, ip: str) -> list[Finding]:
        """Query Shodan API for host information."""
        findings = []
        api_key = self.api_keys.get('shodan', '')

        if not api_key:
            self.log("Shodan API key not configured")
            return findings

        try:
            url = f"https://api.shodan.io/shodan/host/{ip}"
            params = {"key": api_key}
            response = requests.get(url, params=params, timeout=10)

            if response.status_code != 200:
                self.log(f"Shodan API returned {response.status_code}")
                return findings

            data = response.json()

            # Extract open ports
            ports = data.get("ports", [])
            if ports:
                for port in ports[:10]:  # Limit to top 10
                    findings.append(Finding(
                        title=f"Shodan: Open Port {port}",
                        severity=Severity.LOW,
                        description=f"Port {port} is open on {ip} (Shodan data)",
                        affected_component=f"{ip}:{port}",
                        agent_source=self.name,
                        mitre_tactics=["Reconnaissance"],
                        mitre_techniques=["T1596"],  # Search Open Technical Databases
                        evidence=f"Found in Shodan database",
                        confidence="high",
                    ))

            # Extract vulnerabilities
            vulns = data.get("vulns", [])
            if vulns:
                vuln_list = ", ".join(vulns[:5])
                findings.append(Finding(
                    title=f"Shodan: Known Vulnerabilities on {ip}",
                    severity=Severity.MEDIUM,
                    description=f"Shodan reports the following CVEs affecting this host: {vuln_list}",
                    affected_component=ip,
                    agent_source=self.name,
                    cve_ids=vulns[:5],
                    mitre_tactics=["Reconnaissance"],
                    mitre_techniques=["T1596"],
                    evidence=f"Found in Shodan vulnerability data",
                    confidence="medium",
                ))

            # Extract OS
            os_info = data.get("os")
            if os_info:
                findings.append(Finding(
                    title=f"Shodan: Detected OS {os_info}",
                    severity=Severity.INFO,
                    description=f"Shodan detected operating system: {os_info}",
                    affected_component=ip,
                    agent_source=self.name,
                    mitre_tactics=["Reconnaissance"],
                    mitre_techniques=["T1592"],  # Gather Victim Host Information
                    evidence=f"Found in Shodan data",
                    confidence="medium",
                ))

        except requests.RequestException as e:
            self.log(f"Shodan API error: {str(e)}")
        except Exception as e:
            self.log(f"Shodan processing error: {str(e)}")

        return findings

    def _query_censys_ip(self, ip: str) -> list[Finding]:
        """Query Censys API for IP host information."""
        findings = []
        censys_id = self.api_keys.get('censys_id', '')
        censys_secret = self.api_keys.get('censys_secret', '')

        if not censys_id or not censys_secret:
            self.log("Censys credentials not configured")
            return findings

        try:
            url = f"https://censys.io/api/v1/ipv4/{ip}"
            response = requests.get(
                url,
                auth=(censys_id, censys_secret),
                timeout=10,
            )

            if response.status_code != 200:
                self.log(f"Censys API returned {response.status_code}")
                return findings

            data = response.json()

            # Extract protocols/services
            protocols = data.get("protocols", [])
            if protocols:
                for protocol in protocols[:10]:
                    findings.append(Finding(
                        title=f"Censys: Service {protocol}",
                        severity=Severity.LOW,
                        description=f"Censys detected service/protocol: {protocol} on {ip}",
                        affected_component=f"{ip}:{protocol}",
                        agent_source=self.name,
                        mitre_tactics=["Reconnaissance"],
                        mitre_techniques=["T1596"],
                        evidence=f"Found in Censys database",
                        confidence="high",
                    ))

            # Extract location
            location = data.get("location", {})
            if location:
                country = location.get("country_code", "")
                if country:
                    findings.append(Finding(
                        title=f"Censys: Geolocation {country}",
                        severity=Severity.INFO,
                        description=f"IP {ip} is geographically located in {country}",
                        affected_component=ip,
                        agent_source=self.name,
                        mitre_tactics=["Reconnaissance"],
                        mitre_techniques=["T1590"],  # Gather Victim Network Information
                        evidence=f"Found in Censys geolocation data",
                        confidence="high",
                    ))

        except requests.RequestException as e:
            self.log(f"Censys API error: {str(e)}")
        except Exception as e:
            self.log(f"Censys processing error: {str(e)}")

        return findings

    def _query_virustotal(self, target: str) -> list[Finding]:
        """Query VirusTotal for domain/IP reputation."""
        findings = []
        api_key = self.api_keys.get('virustotal', '')

        if not api_key:
            self.log("VirusTotal API key not configured")
            return findings

        try:
            # Determine if target is IP or domain
            if self._is_ip(target):
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
            else:
                url = f"https://www.virustotal.com/api/v3/domains/{target}"

            headers = {"x-apikey": api_key}
            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code != 200:
                self.log(f"VirusTotal API returned {response.status_code}")
                return findings

            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})

            # Check reputation stats
            last_analysis = attributes.get("last_analysis_stats", {})
            malicious = last_analysis.get("malicious", 0)
            suspicious = last_analysis.get("suspicious", 0)

            if malicious > 0:
                severity = Severity.CRITICAL if malicious > 5 else Severity.HIGH
                findings.append(Finding(
                    title=f"VirusTotal: {malicious} Detections",
                    severity=severity,
                    description=f"VirusTotal reports {malicious} security vendors flagged {target} as malicious",
                    affected_component=target,
                    agent_source=self.name,
                    mitre_tactics=["Reconnaissance"],
                    mitre_techniques=["T1593"],  # Search Open Websites/Domains
                    evidence=f"Found {malicious} detections in VirusTotal",
                    confidence="high",
                ))

            if suspicious > 0:
                findings.append(Finding(
                    title=f"VirusTotal: {suspicious} Suspicious Flags",
                    severity=Severity.MEDIUM,
                    description=f"VirusTotal reports {suspicious} security vendors flagged {target} as suspicious",
                    affected_component=target,
                    agent_source=self.name,
                    mitre_tactics=["Reconnaissance"],
                    mitre_techniques=["T1593"],
                    evidence=f"Found {suspicious} suspicious flags in VirusTotal",
                    confidence="medium",
                ))

            # Check categories
            categories = attributes.get("categories", {})
            if categories:
                cat_list = ", ".join(set(categories.values()))
                findings.append(Finding(
                    title=f"VirusTotal: Categorized as {cat_list}",
                    severity=Severity.INFO,
                    description=f"VirusTotal categorizes {target} as: {cat_list}",
                    affected_component=target,
                    agent_source=self.name,
                    mitre_tactics=["Reconnaissance"],
                    mitre_techniques=["T1593"],
                    evidence=f"Found in VirusTotal categories",
                    confidence="high",
                ))

        except requests.RequestException as e:
            self.log(f"VirusTotal API error: {str(e)}")
        except Exception as e:
            self.log(f"VirusTotal processing error: {str(e)}")

        return findings
