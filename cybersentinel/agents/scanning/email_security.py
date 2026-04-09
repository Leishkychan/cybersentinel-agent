"""Email Security Agent — SPF/DKIM/DMARC Analysis.

Analyzes domain email security posture:
- SPF records (all/~all/-all)
- DKIM records (selector coverage)
- DMARC policies (reject/quarantine/none)

Maps to T1566 (Phishing) defensive context.
"""

from __future__ import annotations

import subprocess
import logging
import re
from typing import Optional

from cybersentinel.agents.base import BaseAgent
from cybersentinel.models.finding import Finding, Severity


logger = logging.getLogger(__name__)


class EmailSecurityAgent(BaseAgent):
    """Email security posture analysis (SPF/DKIM/DMARC)."""

    name = "email_security"
    description = "Email authentication analysis (SPF, DKIM, DMARC)"

    # Common DKIM selectors
    DKIM_SELECTORS = [
        "google",
        "default",
        "selector1",
        "selector2",
        "mail",
        "k1",
        "k2",
        "s1",
        "s2",
        "dkim",
    ]

    def analyze(self, target: str, context: dict) -> list[Finding]:
        """Analyze email security for a domain."""
        self.validate(target, f"Email security analysis of {target}")
        self.log(f"Starting email security analysis on {target}")

        findings: list[Finding] = []

        # Extract domain from email or use directly
        domain = self._extract_domain(target)
        if not domain:
            self.log("Invalid domain")
            return findings

        # Check SPF
        spf_findings = self._check_spf(domain)
        findings.extend(spf_findings)

        # Check DMARC
        dmarc_findings = self._check_dmarc(domain)
        findings.extend(dmarc_findings)

        # Check DKIM (multiple selectors)
        dkim_findings = self._check_dkim(domain)
        findings.extend(dkim_findings)

        self.log(f"Email security analysis complete: {len(findings)} findings")
        return findings

    def _extract_domain(self, target: str) -> Optional[str]:
        """Extract domain from email or validate domain."""
        # If it looks like an email, extract domain
        if "@" in target:
            return target.split("@")[1]

        # Otherwise, validate it's a domain
        if "." in target and not target.startswith("http"):
            return target

        return None

    def _check_spf(self, domain: str) -> list[Finding]:
        """Check SPF record."""
        findings = []

        try:
            cmd = ["dig", f"{domain}", "TXT", "+short"]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
            )

            output = result.stdout.strip()
            spf_record = None

            # Find SPF record
            for line in output.split("\n"):
                if "v=spf1" in line:
                    spf_record = line.strip('"')
                    break

            if not spf_record:
                finding = Finding(
                    title="Email Security — No SPF Record",
                    severity=Severity.HIGH,
                    description=f"No SPF record found for {domain}. Without SPF, emails can be spoofed.",
                    affected_component=domain,
                    agent_source=self.name,
                    cwe_ids=["CWE-287"],
                    mitre_tactics=["Delivery"],
                    mitre_techniques=["T1566"],
                    remediation=f"Create an SPF record for {domain}. Example: v=spf1 include:_spf.google.com ~all",
                )
                findings.append(finding)
                return findings

            # Analyze SPF record
            policy = self._extract_spf_policy(spf_record)

            if policy == "+all":
                finding = Finding(
                    title="Email Security — SPF +all (Accept All)",
                    severity=Severity.HIGH,
                    description=f"SPF record ends with '+all', accepting mail from any server. Fails SPF purpose.",
                    affected_component=domain,
                    agent_source=self.name,
                    cwe_ids=["CWE-287"],
                    mitre_tactics=["Delivery"],
                    mitre_techniques=["T1566"],
                    remediation="Replace '+all' with '~all' (soft fail) or '-all' (hard fail). Use specific mechanisms for authorized senders.",
                )
                findings.append(finding)

            elif policy == "?all":
                finding = Finding(
                    title="Email Security — SPF ?all (Neutral)",
                    severity=Severity.MEDIUM,
                    description=f"SPF record ends with '?all', neutral on any server. Does not prevent spoofing.",
                    affected_component=domain,
                    agent_source=self.name,
                    cwe_ids=["CWE-287"],
                    mitre_tactics=["Delivery"],
                    mitre_techniques=["T1566"],
                    remediation="Change '?all' to '-all' (hard fail) after verifying legitimate senders are included.",
                )
                findings.append(finding)

            elif policy == "~all":
                finding = Finding(
                    title="Email Security — SPF Soft Fail (~all)",
                    severity=Severity.LOW,
                    description=f"SPF record ends with '~all', soft failing unauthorized servers. Better than no SPF, but not optimal.",
                    affected_component=domain,
                    agent_source=self.name,
                    cwe_ids=["CWE-287"],
                    mitre_tactics=["Delivery"],
                    mitre_techniques=["T1566"],
                    remediation="Consider using '-all' (hard fail) once confident all legitimate senders are included.",
                    confidence="medium",
                )
                findings.append(finding)

            # Check for too many includes
            include_count = spf_record.count("include:")
            if include_count > 10:
                finding = Finding(
                    title="Email Security — SPF Too Many Includes",
                    severity=Severity.MEDIUM,
                    description=f"SPF record has {include_count} includes. SPF limit is 10 DNS lookups. May hit DNS lookup limit.",
                    affected_component=domain,
                    agent_source=self.name,
                    cwe_ids=["CWE-287"],
                    mitre_tactics=["Delivery"],
                    mitre_techniques=["T1566"],
                    remediation="Reduce number of includes. Combine with existing SPF records or use SPF flattening.",
                )
                findings.append(finding)

        except subprocess.TimeoutExpired:
            self.log("SPF lookup timeout")
        except FileNotFoundError:
            self.log("dig not found")
        except Exception as e:
            self.log(f"SPF check error: {str(e)[:100]}")

        return findings

    def _check_dmarc(self, domain: str) -> list[Finding]:
        """Check DMARC record."""
        findings = []

        try:
            cmd = ["dig", f"_dmarc.{domain}", "TXT", "+short"]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
            )

            output = result.stdout.strip()
            if not output or "NXDOMAIN" in output:
                finding = Finding(
                    title="Email Security — No DMARC Record",
                    severity=Severity.MEDIUM,
                    description=f"No DMARC record found for {domain}. Without DMARC, SPF/DKIM failures cannot trigger actions.",
                    affected_component=domain,
                    agent_source=self.name,
                    cwe_ids=["CWE-287"],
                    mitre_tactics=["Delivery"],
                    mitre_techniques=["T1566"],
                    remediation=f"Create DMARC record for {domain}. Publish _dmarc.{domain} TXT record with policy=reject.",
                )
                findings.append(finding)
                return findings

            # Parse DMARC record
            dmarc_record = output.strip('"')

            # Check policy
            policy_match = re.search(r'p=(\w+)', dmarc_record)
            if policy_match:
                policy = policy_match.group(1)

                if policy == "none":
                    finding = Finding(
                        title="Email Security — DMARC Policy None",
                        severity=Severity.MEDIUM,
                        description=f"DMARC policy is 'none'. Authentication failures are only reported, not rejected.",
                        affected_component=domain,
                        agent_source=self.name,
                        cwe_ids=["CWE-287"],
                        mitre_tactics=["Delivery"],
                        mitre_techniques=["T1566"],
                        remediation="Advance to 'quarantine' then 'reject' after monitoring. Use 'rua' and 'ruf' for reporting.",
                        confidence="medium",
                    )
                    findings.append(finding)

                elif policy == "quarantine":
                    finding = Finding(
                        title="Email Security — DMARC Quarantine (Not Reject)",
                        severity=Severity.LOW,
                        description=f"DMARC policy is 'quarantine'. Failed emails are moved to spam, but not rejected outright.",
                        affected_component=domain,
                        agent_source=self.name,
                        cwe_ids=["CWE-287"],
                        mitre_tactics=["Delivery"],
                        mitre_techniques=["T1566"],
                        remediation="Consider upgrading to 'reject' once SPF/DKIM are fully established.",
                        confidence="medium",
                    )
                    findings.append(finding)

            # Check for reporting
            if "rua=" not in dmarc_record:
                finding = Finding(
                    title="Email Security — No DMARC Aggregate Reporting",
                    severity=Severity.LOW,
                    description=f"DMARC record lacks 'rua' (aggregate reports). Cannot monitor authentication results.",
                    affected_component=domain,
                    agent_source=self.name,
                    cwe_ids=["CWE-200"],
                    mitre_tactics=["Delivery"],
                    mitre_techniques=["T1566"],
                    remediation="Add 'rua=mailto:dmarc@example.com' to DMARC record for reporting.",
                )
                findings.append(finding)

        except subprocess.TimeoutExpired:
            self.log("DMARC lookup timeout")
        except FileNotFoundError:
            self.log("dig not found")
        except Exception as e:
            self.log(f"DMARC check error: {str(e)[:100]}")

        return findings

    def _check_dkim(self, domain: str) -> list[Finding]:
        """Check DKIM records."""
        findings = []

        dkim_found = False

        for selector in self.DKIM_SELECTORS:
            try:
                cmd = ["dig", f"{selector}._domainkey.{domain}", "TXT", "+short"]
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )

                output = result.stdout.strip()
                if output and "NXDOMAIN" not in output:
                    dkim_found = True
                    break

            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue

        if not dkim_found:
            finding = Finding(
                title="Email Security — No DKIM Record",
                severity=Severity.HIGH,
                description=f"No DKIM record found for {domain} (checked selectors: {', '.join(self.DKIM_SELECTORS[:5])})",
                affected_component=domain,
                agent_source=self.name,
                cwe_ids=["CWE-287"],
                mitre_tactics=["Delivery"],
                mitre_techniques=["T1566"],
                remediation=f"Generate DKIM key pair and publish public key as TXT record on {selector}._domainkey.{domain}",
            )
            findings.append(finding)

        return findings

    def _extract_spf_policy(self, spf_record: str) -> Optional[str]:
        """Extract SPF policy (all, ~all, -all, ?all)."""
        # Look for the final all mechanism
        patterns = ["-all", "~all", "+all", "?all"]
        for pattern in patterns:
            if pattern in spf_record:
                return pattern

        return None
