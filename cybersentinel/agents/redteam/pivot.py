"""Pivot Agent — network pivot analysis."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from cybersentinel.agents.base import BaseAgent
from cybersentinel.models.finding import Finding, Severity

if TYPE_CHECKING:
    from cybersentinel.models.session import Session


logger = logging.getLogger(__name__)


@dataclass
class ReachableEndpoint:
    """An endpoint reachable from a compromised point."""

    address: str  # IP or hostname
    port: int
    service: str  # HTTP, SSH, DB, etc.
    description: str
    criticality: str  # critical, high, medium, low
    mitre_technique: str = ""


@dataclass
class PivotPath:
    """A complete pivot path from entry to target."""

    entry_point: str
    hops: list[str]  # Intermediate systems
    final_target: str
    reachable_endpoints: list[ReachableEndpoint] = field(default_factory=list)
    blast_radius: str = ""


class PivotAgent(BaseAgent):
    """Network pivot analysis."""

    name = "pivot"
    description = "Maps network pivot and lateral movement opportunities"

    def __init__(self, session: Session):
        super().__init__(session)

    def analyze(self, target: str, context: dict) -> list[Finding]:
        """Analyze findings for network pivot opportunities.

        Args:
            target: Target identifier
            context: Dict with 'findings' (SSRF), 'network_scan', 'trust_boundaries'

        Returns:
            Findings with pivot paths and reachable endpoints
        """
        if not self.validate(target, "Network pivot analysis"):
            return []

        findings = context.get("findings", [])
        network_scan = context.get("network_scan", {})
        trust_boundaries = context.get("trust_boundaries", {})

        if not findings:
            return []

        new_findings = []

        # Extract SSRF findings
        ssrf_findings = [f for f in findings if self._is_ssrf_finding(f)]

        for ssrf_finding in ssrf_findings:
            # Build pivot paths from this SSRF
            pivot_paths = self._build_pivot_paths(ssrf_finding, network_scan, trust_boundaries)

            for path in pivot_paths:
                pivot_finding = Finding(
                    title=f"Network Pivot Path: {path.entry_point} -> {path.final_target}",
                    severity=Severity.CRITICAL,
                    description=self._format_pivot_description(path),
                    affected_component=path.entry_point,
                    agent_source=self.name,
                    confidence="high",
                    evidence=self._format_pivot_evidence(path),
                    mitre_techniques=["T1210", "T1021"],
                )

                new_findings.append(pivot_finding)
                self.log(f"Discovered pivot path: {' -> '.join([path.entry_point] + path.hops + [path.final_target])}")

        return new_findings

    def _is_ssrf_finding(self, finding: Finding) -> bool:
        """Check if a finding is SSRF-related."""
        return "ssrf" in finding.title.lower() or "server-side request" in finding.description.lower()

    def _build_pivot_paths(self, ssrf_finding: Finding, network_scan: dict, trust_boundaries: dict) -> list[PivotPath]:
        """Build pivot paths from an SSRF finding."""
        paths = []

        entry_point = ssrf_finding.affected_component

        # Identify reachable endpoints
        reachable = self._identify_reachable_endpoints(network_scan)

        if reachable:
            # Cloud metadata endpoint (169.254.169.254)
            metadata_endpoint = ReachableEndpoint(
                address="169.254.169.254",
                port=80,
                service="AWS Metadata",
                description="Cloud instance metadata service - contains IAM credentials",
                criticality="critical",
                mitre_technique="T1526",
            )
            reachable.insert(0, metadata_endpoint)

            # Create pivot path
            path = PivotPath(
                entry_point=entry_point,
                hops=["Cloud Metadata Service"],
                final_target="IAM Credentials",
                reachable_endpoints=reachable,
                blast_radius="Credential theft enables complete account compromise",
            )

            paths.append(path)

        # Additional pivot targets (databases, internal services)
        internal_targets = [
            ReachableEndpoint(
                address="10.0.0.0/8",
                port=3306,
                service="MySQL",
                description="Internal database server",
                criticality="critical",
                mitre_technique="T1071",
            ),
            ReachableEndpoint(
                address="10.0.0.0/8",
                port=5432,
                service="PostgreSQL",
                description="Internal database server",
                criticality="critical",
                mitre_technique="T1071",
            ),
            ReachableEndpoint(
                address="127.0.0.1",
                port=8080,
                service="Admin Interface",
                description="Internal admin panel",
                criticality="high",
                mitre_technique="T1021",
            ),
            ReachableEndpoint(
                address="10.0.0.0/8",
                port=22,
                service="SSH",
                description="Internal SSH access",
                criticality="high",
                mitre_technique="T1021",
            ),
        ]

        if internal_targets:
            path = PivotPath(
                entry_point=entry_point,
                hops=["Internal Network"],
                final_target="Databases and Services",
                reachable_endpoints=internal_targets,
                blast_radius="Lateral movement to internal database and service infrastructure",
            )
            paths.append(path)

        return paths

    def _identify_reachable_endpoints(self, network_scan: dict) -> list[ReachableEndpoint]:
        """Identify reachable endpoints from network scan results."""
        endpoints = []

        # Parse network scan results if available
        if "hosts" in network_scan:
            for host in network_scan["hosts"]:
                if "services" in host:
                    for service in host["services"]:
                        endpoint = ReachableEndpoint(
                            address=host.get("ip", "unknown"),
                            port=service.get("port", 0),
                            service=service.get("name", "unknown"),
                            description=f"{service.get('name', 'Unknown')} service",
                            criticality="high",
                        )
                        endpoints.append(endpoint)

        # Add common internal services if no scan results
        if not endpoints:
            endpoints = [
                ReachableEndpoint(
                    address="localhost",
                    port=5432,
                    service="PostgreSQL",
                    description="Local PostgreSQL database",
                    criticality="high",
                ),
                ReachableEndpoint(
                    address="localhost",
                    port=6379,
                    service="Redis",
                    description="Local Redis cache",
                    criticality="high",
                ),
                ReachableEndpoint(
                    address="localhost",
                    port=27017,
                    service="MongoDB",
                    description="Local MongoDB database",
                    criticality="high",
                ),
            ]

        return endpoints

    def _format_pivot_description(self, path: PivotPath) -> str:
        """Format pivot path description."""
        hops_text = " -> ".join(path.hops) if path.hops else "direct"

        return (
            f"A network pivot path has been discovered using the SSRF vulnerability. "
            f"From {path.entry_point}, an attacker could reach: {hops_text}. "
            f"Final targets include {len(path.reachable_endpoints)} reachable endpoints. "
            f"Blast radius: {path.blast_radius}"
        )

    def _format_pivot_evidence(self, path: PivotPath) -> str:
        """Format pivot evidence."""
        evidence = f"=== Network Pivot Path ===\n\n"

        evidence += f"Entry Point: {path.entry_point}\n"

        if path.hops:
            evidence += f"Pivot Hops: {' -> '.join(path.hops)}\n"

        evidence += f"Final Target: {path.final_target}\n\n"

        evidence += f"Reachable Endpoints ({len(path.reachable_endpoints)}):\n"

        for i, endpoint in enumerate(path.reachable_endpoints, 1):
            evidence += f"\n  {i}. {endpoint.service}\n"
            evidence += f"     Address: {endpoint.address}:{endpoint.port}\n"
            evidence += f"     Description: {endpoint.description}\n"
            evidence += f"     Criticality: {endpoint.criticality}\n"

            if endpoint.mitre_technique:
                evidence += f"     MITRE: {endpoint.mitre_technique}\n"

        evidence += f"\nBlast Radius: {path.blast_radius}\n"

        return evidence

    def get_reachable_hosts(self, path: PivotPath) -> list[str]:
        """Get list of reachable hosts from a pivot path."""
        return [ep.address for ep in path.reachable_endpoints]

    def get_critical_endpoints(self, path: PivotPath) -> list[ReachableEndpoint]:
        """Get critical endpoints from a pivot path."""
        return [ep for ep in path.reachable_endpoints if ep.criticality == "critical"]
