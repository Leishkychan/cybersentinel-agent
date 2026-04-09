"""Subdomain Enumeration Agent — Layer 1 Reconnaissance.

Wraps subfinder and amass to discover subdomains of target domain.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from typing import TYPE_CHECKING

from cybersentinel.agents.base import BaseAgent
from cybersentinel.models.finding import Finding, Severity

if TYPE_CHECKING:
    from cybersentinel.models.session import Session


class SubdomainAgent(BaseAgent):
    """Discovers subdomains using subfinder and amass."""

    name = "subdomain"
    description = "Subdomain enumeration — discovers subdomains of target domain"

    def __init__(self, session: Session):
        super().__init__(session)

    def analyze(self, target: str, context: dict) -> list[Finding]:
        """Discover subdomains for the target domain.

        Args:
            target: The target domain (e.g., 'example.com')
            context: Additional context, typically contains {'target': 'example.com'}

        Returns:
            List of Finding objects, one per discovered subdomain
        """
        self.validate(target, f"Subdomain enumeration of {target}")
        self.log(f"Starting subdomain enumeration on {target}")

        findings: list[Finding] = []
        subdomains = set()

        # Try subfinder first (fast)
        subfinder_subs = self._run_subfinder(target)
        if subfinder_subs:
            self.log(f"subfinder found {len(subfinder_subs)} subdomains")
            subdomains.update(subfinder_subs)

        # Then try amass (thorough)
        amass_subs = self._run_amass(target)
        if amass_subs:
            self.log(f"amass found {len(amass_subs)} subdomains")
            subdomains.update(amass_subs)

        # Convert to findings
        for subdomain in sorted(subdomains):
            findings.append(Finding(
                title=f"Subdomain Discovered: {subdomain}",
                severity=Severity.INFO,
                description=f"Subdomain '{subdomain}' of target '{target}' was discovered through subdomain enumeration.",
                affected_component=subdomain,
                agent_source=self.name,
                mitre_tactics=["Reconnaissance"],
                mitre_techniques=["T1596"],  # Search Open Technical Databases
                evidence=f"Found via subdomain enumeration (subfinder/amass)",
                confidence="high",
            ))

        self.log(f"Subdomain enumeration complete: {len(findings)} unique subdomains found")
        return findings

    def _run_subfinder(self, domain: str) -> set[str]:
        """Run subfinder and return discovered subdomains."""
        try:
            cmd = ["subfinder", "-d", domain, "-silent", "-json"]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )

            if result.returncode != 0:
                self.log(f"subfinder failed: {result.stderr}")
                return set()

            subdomains = set()
            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    if "host" in data:
                        subdomains.add(data["host"])
                except json.JSONDecodeError:
                    pass

            return subdomains

        except FileNotFoundError:
            self.log("subfinder not found on system")
            return set()
        except subprocess.TimeoutExpired:
            self.log("subfinder timed out")
            return set()
        except Exception as e:
            self.log(f"subfinder error: {str(e)}")
            return set()

    def _run_amass(self, domain: str) -> set[str]:
        """Run amass and return discovered subdomains."""
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                output_file = f.name

            cmd = ["amass", "enum", "-d", domain, "-json", output_file]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.returncode != 0:
                self.log(f"amass failed: {result.stderr}")
                return set()

            subdomains = set()
            try:
                with open(output_file, 'r') as f:
                    for line in f:
                        if not line.strip():
                            continue
                        try:
                            data = json.loads(line)
                            if "name" in data:
                                subdomains.add(data["name"])
                        except json.JSONDecodeError:
                            pass
            except FileNotFoundError:
                self.log(f"amass output file not found: {output_file}")

            return subdomains

        except FileNotFoundError:
            self.log("amass not found on system")
            return set()
        except subprocess.TimeoutExpired:
            self.log("amass timed out")
            return set()
        except Exception as e:
            self.log(f"amass error: {str(e)}")
            return set()
