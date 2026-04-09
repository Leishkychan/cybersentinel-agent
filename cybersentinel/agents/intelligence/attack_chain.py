"""Attack Chain Agent — discovers and maps attack paths."""

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
class AttackStep:
    """A single step in an attack chain."""

    phase: str  # Initial Access, Execution, Persistence, etc.
    description: str
    finding_id: str
    detection_probability: float  # 0.0-1.0


@dataclass
class AttackChain:
    """A complete attack path from initial access to exfiltration."""

    steps: list[AttackStep]
    combined_severity: str
    blast_radius: str
    critical_finding: str  # Finding that if fixed, breaks the chain

    def get_detection_probability(self) -> float:
        """Calculate cumulative detection probability."""
        if not self.steps:
            return 0.0
        product = 1.0
        for step in self.steps:
            product *= (1.0 - step.detection_probability)
        return 1.0 - product


class AttackChainAgent(BaseAgent):
    """Discovers and maps attack paths."""

    name = "attack_chain"
    description = "Discovers and maps complete attack chains"

    def __init__(self, session: Session):
        super().__init__(session)
        self.attack_phases = [
            "Initial Access",
            "Execution",
            "Persistence",
            "Privilege Escalation",
            "Lateral Movement",
            "Exfiltration",
        ]

    def analyze(self, target: str, context: dict) -> list[Finding]:
        """Analyze all findings to discover attack chains.

        Args:
            target: Target identifier
            context: Dict with 'findings' key containing Finding objects

        Returns:
            New findings showing complete attack chains
        """
        if not self.validate(target, "Attack chain analysis"):
            return []

        findings = context.get("findings", [])
        if not findings:
            return []

        new_findings = []

        # Build attack chains
        chains = self._build_attack_chains(findings)

        for chain in chains:
            chain_finding = Finding(
                title=f"Complete attack chain: {chain.steps[0].phase} -> {chain.steps[-1].phase}",
                severity=Severity.CRITICAL if chain.combined_severity == "CRITICAL" else Severity.HIGH,
                description=self._format_chain_description(chain),
                affected_component=target,
                agent_source=self.name,
                confidence="high",
                evidence=self._format_chain_evidence(chain),
            )

            # Add MITRE techniques from all steps
            chain_finding.mitre_techniques = self._extract_chain_techniques(chain)

            new_findings.append(chain_finding)
            self.log(f"Discovered attack chain with {len(chain.steps)} steps")

        return new_findings

    def _build_attack_chains(self, findings: list[Finding]) -> list[AttackChain]:
        """Build attack chains from findings."""
        chains = []

        # Group findings by phase
        phases_to_findings = self._map_findings_to_phases(findings)

        # Check if we have a chain progression
        if self._has_chain_progression(phases_to_findings):
            steps = self._build_chain_steps(phases_to_findings)
            chain = AttackChain(
                steps=steps,
                combined_severity=self._calculate_combined_severity(steps),
                blast_radius=self._calculate_blast_radius(steps),
                critical_finding=self._find_critical_finding(steps),
            )
            chains.append(chain)
            self.log(f"Built attack chain: {' -> '.join([s.phase for s in steps])}")

        return chains

    def _map_findings_to_phases(self, findings: list[Finding]) -> dict[str, list[Finding]]:
        """Map findings to attack phases."""
        phase_map = {phase: [] for phase in self.attack_phases}

        for finding in findings:
            phase = self._classify_finding_phase(finding)
            if phase in phase_map:
                phase_map[phase].append(finding)

        return phase_map

    def _classify_finding_phase(self, finding: Finding) -> str:
        """Classify a finding into an attack phase."""
        title_lower = finding.title.lower()
        description_lower = finding.description.lower()

        phase_keywords = {
            "Initial Access": ["exposed", "public", "unprotected", "internet-facing", "weak auth", "phishing"],
            "Execution": ["rce", "command execution", "script", "shell", "code injection"],
            "Persistence": ["backdoor", "persistence", "privilege", "scheduled", "startup", "registry"],
            "Privilege Escalation": ["privilege escalation", "privilege", "sudo", "admin", "root"],
            "Lateral Movement": ["lateral", "pivot", "network", "trust", "ssrf", "spread"],
            "Exfiltration": ["exfiltration", "data leak", "disclosure", "information", "sensitive data"],
        }

        for phase, keywords in phase_keywords.items():
            for keyword in keywords:
                if keyword in title_lower or keyword in description_lower:
                    return phase

        return "Initial Access"  # Default phase

    def _has_chain_progression(self, phases_to_findings: dict[str, list[Finding]]) -> bool:
        """Check if findings represent a complete chain."""
        finding_phases = [p for p, f in phases_to_findings.items() if f]
        return len(finding_phases) >= 3

    def _build_chain_steps(self, phases_to_findings: dict[str, list[Finding]]) -> list[AttackStep]:
        """Build attack chain steps."""
        steps = []

        for phase in self.attack_phases:
            findings = phases_to_findings.get(phase, [])
            if not findings:
                continue

            finding = findings[0]  # Use first finding for this phase
            step = AttackStep(
                phase=phase,
                description=finding.title,
                finding_id=finding.affected_component,
                detection_probability=self._estimate_detection_probability(finding),
            )
            steps.append(step)

        return steps

    def _estimate_detection_probability(self, finding: Finding) -> float:
        """Estimate detection probability for a finding (0.0-1.0)."""
        base_probability = 0.5

        if finding.severity.value == "critical":
            base_probability += 0.3
        elif finding.severity.value == "high":
            base_probability += 0.2
        elif finding.severity.value == "low":
            base_probability -= 0.2

        return min(max(base_probability, 0.1), 0.9)

    def _calculate_combined_severity(self, steps: list[AttackStep]) -> str:
        """Calculate combined severity for a chain."""
        if len(steps) >= 5:
            return "CRITICAL"
        if len(steps) >= 3:
            return "HIGH"
        return "MEDIUM"

    def _calculate_blast_radius(self, steps: list[AttackStep]) -> str:
        """Calculate blast radius of the chain."""
        if len(steps) >= 5:
            return "System-wide compromise, data exfiltration, persistence"
        if len(steps) >= 3:
            return "Privilege escalation, lateral movement, potential exfiltration"
        return "Limited to initial access point"

    def _find_critical_finding(self, steps: list[AttackStep]) -> str:
        """Identify the finding that if fixed, breaks the chain."""
        if not steps:
            return "Unknown"
        # The initial access finding is most critical
        return steps[0].finding_id

    def _extract_chain_techniques(self, chain: AttackChain) -> list[str]:
        """Extract MITRE techniques from chain steps."""
        techniques = set()
        phase_to_techniques = {
            "Initial Access": ["T1190", "T1566", "T1598", "T1595"],
            "Execution": ["T1059", "T1559", "T1072", "T1053"],
            "Persistence": ["T1098", "T1547", "T1136", "T1543"],
            "Privilege Escalation": ["T1134", "T1548", "T1611", "T1547"],
            "Lateral Movement": ["T1570", "T1021", "T1570", "T1570"],
            "Exfiltration": ["T1020", "T1030", "T1048", "T1041"],
        }

        for step in chain.steps:
            if step.phase in phase_to_techniques:
                techniques.update(phase_to_techniques[step.phase])

        return sorted(list(techniques))[:5]

    def _format_chain_description(self, chain: AttackChain) -> str:
        """Format attack chain description."""
        steps_desc = " → ".join([s.phase for s in chain.steps])
        return (
            f"A complete attack chain has been discovered: {steps_desc}. "
            f"An attacker could follow this path to achieve system compromise and data exfiltration. "
            f"Blast radius: {chain.blast_radius} "
            f"Detection probability: {chain.get_detection_probability():.0%}"
        )

    def _format_chain_evidence(self, chain: AttackChain) -> str:
        """Format attack chain evidence."""
        evidence = "Attack Chain Steps:\n"
        for i, step in enumerate(chain.steps, 1):
            evidence += f"\n{i}. {step.phase}\n"
            evidence += f"   Description: {step.description}\n"
            evidence += f"   Detection Probability: {step.detection_probability:.0%}\n"
            evidence += f"   Finding: {step.finding_id}\n"

        evidence += f"\nCombined Severity: {chain.combined_severity}\n"
        evidence += f"Cumulative Detection Probability: {chain.get_detection_probability():.0%}\n"
        evidence += f"Critical Finding to Fix: {chain.critical_finding}\n"

        return evidence
