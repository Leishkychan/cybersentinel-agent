"""DNS Intelligence Agent — Layer 1 Reconnaissance.

Gathers DNS records, WHOIS data, and certificate transparency data.
"""

from __future__ import annotations

import json
import re
import subprocess
from typing import TYPE_CHECKING

from cybersentinel.agents.base import BaseAgent
from cybersentinel.models.finding import Finding, Severity

if TYPE_CHECKING:
    from cybersentinel.models.session import Session

try:
    import requests
except ImportError:
    requests = None


class DNSIntelAgent(BaseAgent):
    """Gathers DNS intelligence using dig, whois, and certificate transparency."""

    name = "dns_intel"
    description = "DNS intelligence — gathers DNS records, WHOIS, and CT logs"

    def __init__(self, session: Session):
        super().__init__(session)

    def analyze(self, target: str, context: dict) -> list[Finding]:
        """Gather DNS intelligence on target domain.

        Args:
            target: The target domain (e.g., 'example.com')
            context: Additional context

        Returns:
            List of Finding objects with DNS, WHOIS, and CT information
        """
        self.validate(target, f"DNS intelligence gathering on {target}")
        self.log(f"Starting DNS intelligence gathering on {target}")

        findings: list[Finding] = []

        # Query DNS records
        dns_findings = self._query_dns(target)
        findings.extend(dns_findings)

        # Get WHOIS data
        whois_findings = self._query_whois(target)
        findings.extend(whois_findings)

        # Query certificate transparency
        ct_findings = self._query_certificate_transparency(target)
        findings.extend(ct_findings)

        self.log(f"DNS intelligence gathering complete: {len(findings)} findings")
        return findings

    def _query_dns(self, domain: str) -> list[Finding]:
        """Query DNS records using dig."""
        findings = []
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

        for record_type in record_types:
            records = self._run_dig(domain, record_type)
            findings.extend(records)

        return findings

    def _run_dig(self, domain: str, record_type: str) -> list[Finding]:
        """Run dig for a specific record type."""
        findings = []

        try:
            cmd = ["dig", f"{domain}", record_type, "+short"]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode != 0:
                self.log(f"dig failed for {domain} {record_type}")
                return findings

            output = result.stdout.strip()
            if not output:
                return findings

            # Parse records
            records = [r.strip() for r in output.split('\n') if r.strip()]

            if record_type == "A":
                for ip in records:
                    if self._is_valid_ip(ip):
                        findings.append(Finding(
                            title=f"DNS A Record: {domain} -> {ip}",
                            severity=Severity.INFO,
                            description=f"DNS A record resolves {domain} to IP {ip}",
                            affected_component=domain,
                            agent_source=self.name,
                            mitre_tactics=["Reconnaissance"],
                            mitre_techniques=["T1590"],  # Gather Victim Network Information
                            evidence=f"dig {domain} A",
                            confidence="high",
                        ))

            elif record_type == "AAAA":
                for ip in records:
                    if self._is_valid_ipv6(ip):
                        findings.append(Finding(
                            title=f"DNS AAAA Record: {domain} -> {ip}",
                            severity=Severity.INFO,
                            description=f"DNS AAAA record resolves {domain} to IPv6 {ip}",
                            affected_component=domain,
                            agent_source=self.name,
                            mitre_tactics=["Reconnaissance"],
                            mitre_techniques=["T1590"],
                            evidence=f"dig {domain} AAAA",
                            confidence="high",
                        ))

            elif record_type == "MX":
                for mx in records:
                    findings.append(Finding(
                        title=f"DNS MX Record: {mx}",
                        severity=Severity.INFO,
                        description=f"Mail server for {domain}: {mx}",
                        affected_component=domain,
                        agent_source=self.name,
                        mitre_tactics=["Reconnaissance"],
                        mitre_techniques=["T1590"],
                        evidence=f"dig {domain} MX",
                        confidence="high",
                    ))

            elif record_type == "NS":
                for ns in records:
                    findings.append(Finding(
                        title=f"DNS NS Record: {ns}",
                        severity=Severity.INFO,
                        description=f"Name server for {domain}: {ns}",
                        affected_component=domain,
                        agent_source=self.name,
                        mitre_tactics=["Reconnaissance"],
                        mitre_techniques=["T1590"],
                        evidence=f"dig {domain} NS",
                        confidence="high",
                    ))

            elif record_type == "TXT":
                for txt in records:
                    # Check for SPF, DMARC, etc.
                    if txt.startswith("v=spf1"):
                        findings.append(Finding(
                            title=f"DNS SPF Record Detected",
                            severity=Severity.INFO,
                            description=f"SPF policy for {domain}: {txt}",
                            affected_component=domain,
                            agent_source=self.name,
                            mitre_tactics=["Reconnaissance"],
                            mitre_techniques=["T1590"],
                            evidence=f"dig {domain} TXT",
                            confidence="high",
                        ))
                    elif txt.startswith("v=DMARC1"):
                        findings.append(Finding(
                            title=f"DNS DMARC Record Detected",
                            severity=Severity.INFO,
                            description=f"DMARC policy for {domain}: {txt}",
                            affected_component=domain,
                            agent_source=self.name,
                            mitre_tactics=["Reconnaissance"],
                            mitre_techniques=["T1590"],
                            evidence=f"dig {domain} TXT",
                            confidence="high",
                        ))
                    else:
                        findings.append(Finding(
                            title=f"DNS TXT Record: {domain}",
                            severity=Severity.INFO,
                            description=f"TXT record for {domain}: {txt}",
                            affected_component=domain,
                            agent_source=self.name,
                            mitre_tactics=["Reconnaissance"],
                            mitre_techniques=["T1590"],
                            evidence=f"dig {domain} TXT",
                            confidence="high",
                        ))

            elif record_type == "CNAME":
                for cname in records:
                    findings.append(Finding(
                        title=f"DNS CNAME: {domain} -> {cname}",
                        severity=Severity.INFO,
                        description=f"CNAME alias for {domain}: {cname}",
                        affected_component=domain,
                        agent_source=self.name,
                        mitre_tactics=["Reconnaissance"],
                        mitre_techniques=["T1590"],
                        evidence=f"dig {domain} CNAME",
                        confidence="high",
                    ))

            elif record_type == "SOA":
                for soa in records:
                    findings.append(Finding(
                        title=f"DNS SOA Record: {domain}",
                        severity=Severity.INFO,
                        description=f"SOA record for {domain}: {soa}",
                        affected_component=domain,
                        agent_source=self.name,
                        mitre_tactics=["Reconnaissance"],
                        mitre_techniques=["T1590"],
                        evidence=f"dig {domain} SOA",
                        confidence="high",
                    ))

        except FileNotFoundError:
            self.log("dig not found on system")
        except subprocess.TimeoutExpired:
            self.log(f"dig timed out for {domain} {record_type}")
        except Exception as e:
            self.log(f"dig error: {str(e)}")

        return findings

    def _query_whois(self, domain: str) -> list[Finding]:
        """Query WHOIS data using whois command."""
        findings = []

        try:
            cmd = ["whois", domain]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                self.log(f"whois failed for {domain}")
                return findings

            output = result.stdout

            # Extract registrar
            registrar_match = re.search(r"Registrar:\s*(.+)", output)
            if registrar_match:
                registrar = registrar_match.group(1).strip()
                findings.append(Finding(
                    title=f"WHOIS: Registrar {registrar}",
                    severity=Severity.INFO,
                    description=f"Domain {domain} is registered with: {registrar}",
                    affected_component=domain,
                    agent_source=self.name,
                    mitre_tactics=["Reconnaissance"],
                    mitre_techniques=["T1590"],
                    evidence=f"whois {domain}",
                    confidence="high",
                ))

            # Extract registrant organization
            org_match = re.search(r"Registrant Organization:\s*(.+)", output)
            if org_match:
                org = org_match.group(1).strip()
                findings.append(Finding(
                    title=f"WHOIS: Registrant Organization {org}",
                    severity=Severity.INFO,
                    description=f"Domain {domain} is registered to: {org}",
                    affected_component=domain,
                    agent_source=self.name,
                    mitre_tactics=["Reconnaissance"],
                    mitre_techniques=["T1590"],
                    evidence=f"whois {domain}",
                    confidence="high",
                ))

            # Extract name servers
            ns_matches = re.findall(r"Name Server:\s*(.+)", output)
            if ns_matches:
                for ns in ns_matches[:5]:  # Limit to first 5
                    findings.append(Finding(
                        title=f"WHOIS: Name Server {ns.strip()}",
                        severity=Severity.INFO,
                        description=f"Name server for {domain}: {ns.strip()}",
                        affected_component=domain,
                        agent_source=self.name,
                        mitre_tactics=["Reconnaissance"],
                        mitre_techniques=["T1590"],
                        evidence=f"whois {domain}",
                        confidence="high",
                    ))

            # Check expiration
            expiry_match = re.search(r"Expir(?:y|ation) Date:\s*(.+)", output)
            if expiry_match:
                expiry = expiry_match.group(1).strip()
                findings.append(Finding(
                    title=f"WHOIS: Domain Expiration {expiry}",
                    severity=Severity.INFO,
                    description=f"Domain {domain} expires: {expiry}",
                    affected_component=domain,
                    agent_source=self.name,
                    mitre_tactics=["Reconnaissance"],
                    mitre_techniques=["T1590"],
                    evidence=f"whois {domain}",
                    confidence="high",
                ))

        except FileNotFoundError:
            self.log("whois not found on system")
        except subprocess.TimeoutExpired:
            self.log(f"whois timed out for {domain}")
        except Exception as e:
            self.log(f"whois error: {str(e)}")

        return findings

    def _query_certificate_transparency(self, domain: str) -> list[Finding]:
        """Query certificate transparency logs via crt.sh API."""
        findings = []

        if not requests:
            self.log("requests library not available for CT query")
            return findings

        try:
            url = f"https://crt.sh/?q={domain}&output=json"
            response = requests.get(url, timeout=10)

            if response.status_code != 200:
                self.log(f"crt.sh API returned {response.status_code}")
                return findings

            certs = response.json()
            if not certs:
                return findings

            # Extract unique domain names from certificates
            cert_domains = set()
            for cert in certs:
                if "name_value" in cert:
                    names = cert["name_value"].split('\n')
                    cert_domains.update(names)

            # Report discovered domains from CT logs
            for cert_domain in sorted(cert_domains):
                cert_domain = cert_domain.strip()
                if cert_domain and cert_domain != domain:
                    findings.append(Finding(
                        title=f"Certificate Transparency: {cert_domain}",
                        severity=Severity.INFO,
                        description=f"Domain {cert_domain} found in SSL certificate for {domain} (CT logs)",
                        affected_component=cert_domain,
                        agent_source=self.name,
                        mitre_tactics=["Reconnaissance"],
                        mitre_techniques=["T1596"],  # Search Open Technical Databases
                        evidence=f"Found in certificate transparency logs (crt.sh)",
                        confidence="high",
                    ))

            if findings:
                self.log(f"Certificate transparency found {len(findings)} related domains")

        except requests.RequestException as e:
            self.log(f"crt.sh API error: {str(e)}")
        except (json.JSONDecodeError, TypeError) as e:
            self.log(f"crt.sh parsing error: {str(e)}")
        except Exception as e:
            self.log(f"CT query error: {str(e)}")

        return findings

    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is a valid IPv4 address."""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    def _is_valid_ipv6(self, ip: str) -> bool:
        """Check if string is a valid IPv6 address."""
        try:
            import ipaddress
            ipaddress.IPv6Address(ip)
            return True
        except (ValueError, ImportError):
            return ':' in ip and all(c in '0123456789abcdefABCDEF:' for c in ip)
