"""Threat Actor Agent — maps findings to known threat groups."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from cybersentinel.agents.base import BaseAgent
from cybersentinel.models.finding import Finding, Severity

if TYPE_CHECKING:
    from cybersentinel.models.session import Session


logger = logging.getLogger(__name__)


class ThreatActorProfile:
    """Profile for a known threat group."""

    def __init__(
        self,
        name: str,
        aliases: list[str],
        motivation: str,
        target_industries: list[str],
        known_cves: list[str],
        mitre_techniques: list[str],
    ):
        self.name = name
        self.aliases = aliases
        self.motivation = motivation
        self.target_industries = target_industries
        self.known_cves = known_cves
        self.mitre_techniques = mitre_techniques


class ThreatActorAgent(BaseAgent):
    """Maps findings to known threat groups."""

    name = "threat_actor"
    description = "Maps findings to known threat actor groups"

    def __init__(self, session: Session):
        super().__init__(session)
        self.threat_groups = self._initialize_threat_groups()

    def analyze(self, target: str, context: dict) -> list[Finding]:
        """Analyze findings for threat actor correlations.

        Args:
            target: Target identifier
            context: Dict with 'findings' key containing Finding objects

        Returns:
            New findings showing threat group matches
        """
        if not self.validate(target, "Threat actor analysis"):
            return []

        findings = context.get("findings", [])
        if not findings:
            return []

        new_findings = []
        analyzed_groups = set()

        for finding in findings:
            matched_groups = self._match_threat_groups(finding)

            for group, confidence in matched_groups:
                group_key = group.name
                if group_key in analyzed_groups:
                    continue
                analyzed_groups.add(group_key)

                threat_finding = Finding(
                    title=f"Activity matching {group.name} ({group.aliases[0]})",
                    severity=Severity.INFO,
                    description=self._format_group_description(group, finding, confidence),
                    affected_component=target,
                    agent_source=self.name,
                    confidence="high" if confidence > 0.7 else "medium",
                    evidence=self._format_group_evidence(group, finding),
                )

                # Map MITRE techniques
                threat_finding.mitre_techniques = group.mitre_techniques[:5]
                threat_finding.mitre_tactics = self._get_tactics_from_techniques(group.mitre_techniques)

                new_findings.append(threat_finding)
                self.log(f"Matched threat group: {group.name} (confidence: {confidence:.2f})")

        return new_findings

    def _match_threat_groups(self, finding: Finding) -> list[tuple[ThreatActorProfile, float]]:
        """Match a finding against threat groups, return matches with confidence scores."""
        matches = []

        for group in self.threat_groups.values():
            confidence = 0.0

            # Check CVE matches
            cve_matches = len([cve for cve in finding.cve_ids if cve in group.known_cves])
            if cve_matches > 0:
                confidence += min(cve_matches * 0.3, 0.5)

            # Check MITRE technique matches
            technique_matches = len([t for t in finding.mitre_techniques if t in group.mitre_techniques])
            if technique_matches > 0:
                confidence += min(technique_matches * 0.25, 0.5)

            if confidence > 0.3:
                matches.append((group, confidence))

        return sorted(matches, key=lambda x: x[1], reverse=True)

    def _format_group_description(self, group: ThreatActorProfile, finding: Finding, confidence: float) -> str:
        """Format threat actor finding description."""
        return (
            f"Vulnerabilities and techniques in your stack match known activities of {group.name} "
            f"({', '.join(group.aliases)}). This threat group is known for {group.motivation} operations "
            f"targeting {', '.join(group.target_industries)}. Confidence: {confidence:.0%}."
        )

    def _format_group_evidence(self, group: ThreatActorProfile, finding: Finding) -> str:
        """Format threat actor evidence."""
        evidence = f"Threat Group: {group.name}\n"
        evidence += f"Aliases: {', '.join(group.aliases)}\n"
        evidence += f"Motivation: {group.motivation}\n"
        evidence += f"Target Industries: {', '.join(group.target_industries)}\n"
        evidence += f"Known CVEs: {', '.join(group.known_cves[:5])}\n"
        evidence += f"Known Techniques: {', '.join(group.mitre_techniques[:5])}\n"
        return evidence

    def _get_tactics_from_techniques(self, techniques: list[str]) -> list[str]:
        """Extract tactics from MITRE techniques (simplified)."""
        tactics = set()
        technique_to_tactic = {
            "T1595": "Reconnaissance",
            "T1190": "Initial Access",
            "T1059": "Execution",
            "T1547": "Persistence",
            "T1134": "Defense Evasion",
            "T1548": "Privilege Escalation",
            "T1021": "Lateral Movement",
            "T1041": "Exfiltration",
            "T1098": "Persistence",
            "T1197": "Defense Evasion",
        }
        for tech in techniques:
            if tech in technique_to_tactic:
                tactics.add(technique_to_tactic[tech])
        return list(tactics)

    def _initialize_threat_groups(self) -> dict[str, ThreatActorProfile]:
        """Initialize known threat actor database."""
        return {
            "apt28": ThreatActorProfile(
                name="APT28",
                aliases=["Fancy Bear", "Sofacy", "Pawn Storm"],
                motivation="Espionage",
                target_industries=["Government", "Defense", "Media"],
                known_cves=["CVE-2021-44228", "CVE-2021-35617", "CVE-2019-2725"],
                mitre_techniques=["T1595", "T1190", "T1059", "T1078", "T1021", "T1041"],
            ),
            "lazarus": ThreatActorProfile(
                name="Lazarus Group",
                aliases=["Hidden Cobra", "ZINC", "Labyrinth Chollima"],
                motivation="Financial, Espionage, Destruction",
                target_industries=["Finance", "Healthcare", "Manufacturing"],
                known_cves=["CVE-2017-9822", "CVE-2019-0604", "CVE-2021-44228"],
                mitre_techniques=["T1566", "T1059", "T1547", "T1140", "T1021", "T1485"],
            ),
            "fin7": ThreatActorProfile(
                name="FIN7",
                aliases=["Carbanak", "TA505", "Scarlet Widow"],
                motivation="Financial",
                target_industries=["Finance", "Retail", "Hospitality"],
                known_cves=["CVE-2018-4878", "CVE-2017-0199", "CVE-2020-0688"],
                mitre_techniques=["T1566", "T1566", "T1059", "T1059", "T1021", "T1041"],
            ),
            "apt29": ThreatActorProfile(
                name="APT29",
                aliases=["Cozy Bear", "The Dukes", "Midnight Blizzard"],
                motivation="Espionage",
                target_industries=["Government", "Defense", "Healthcare"],
                known_cves=["CVE-2021-44228", "CVE-2021-27065", "CVE-2021-34523"],
                mitre_techniques=["T1566", "T1059", "T1547", "T1562", "T1021", "T1041"],
            ),
            "equation_group": ThreatActorProfile(
                name="Equation Group",
                aliases=["Equation Group", "NSO Group"],
                motivation="Espionage",
                target_industries=["Government", "Telecommunications", "Energy"],
                known_cves=["CVE-2017-5645", "CVE-2017-0199", "CVE-2019-0604"],
                mitre_techniques=["T1598", "T1566", "T1059", "T1547", "T1548", "T1021"],
            ),
            "apt41": ThreatActorProfile(
                name="APT41",
                aliases=["Winnti", "Barium", "Wicked Panda"],
                motivation="Financial, Espionage",
                target_industries=["Healthcare", "Telecommunications", "Government"],
                known_cves=["CVE-2019-19781", "CVE-2020-1938", "CVE-2021-44228"],
                mitre_techniques=["T1566", "T1190", "T1059", "T1547", "T1134", "T1021"],
            ),
            "wizard_spider": ThreatActorProfile(
                name="Wizard Spider",
                aliases=["TrickBot", "Anchormail", "Gorgon Group"],
                motivation="Financial",
                target_industries=["Finance", "Healthcare", "Retail"],
                known_cves=["CVE-2021-44228", "CVE-2020-1938", "CVE-2017-5645"],
                mitre_techniques=["T1566", "T1566", "T1059", "T1059", "T1021", "T1486"],
            ),
            "turla": ThreatActorProfile(
                name="Turla",
                aliases=["Carbon Spider", "Uroburos", "Snake"],
                motivation="Espionage",
                target_industries=["Government", "Defense", "Aerospace"],
                known_cves=["CVE-2021-44228", "CVE-2019-0604", "CVE-2018-4878"],
                mitre_techniques=["T1595", "T1598", "T1059", "T1547", "T1562", "T1021"],
            ),
            "emotet": ThreatActorProfile(
                name="Emotet",
                aliases=["Heodo", "Botnet", "Banking Trojan"],
                motivation="Financial",
                target_industries=["Finance", "Retail", "Healthcare"],
                known_cves=["CVE-2017-0199", "CVE-2018-4878", "CVE-2020-1938"],
                mitre_techniques=["T1566", "T1566", "T1059", "T1059", "T1021", "T1041"],
            ),
            "darkside": ThreatActorProfile(
                name="DarkSide",
                aliases=["DarkSide Ransomware", "BlackMatter"],
                motivation="Financial",
                target_industries=["Energy", "Manufacturing", "Healthcare"],
                known_cves=["CVE-2021-44228", "CVE-2021-1732", "CVE-2021-34527"],
                mitre_techniques=["T1190", "T1059", "T1486", "T1041", "T1485"],
            ),
            "revil": ThreatActorProfile(
                name="REvil",
                aliases=["Sodinokibi", "Pinchy Spider"],
                motivation="Financial",
                target_industries=["Healthcare", "Government", "Technology"],
                known_cves=["CVE-2021-3129", "CVE-2021-23785", "CVE-2021-39646"],
                mitre_techniques=["T1190", "T1059", "T1486", "T1041", "T1005"],
            ),
            "conti": ThreatActorProfile(
                name="Conti",
                aliases=["Conti Ransomware", "Ryuk"],
                motivation="Financial",
                target_industries=["Healthcare", "Finance", "Manufacturing"],
                known_cves=["CVE-2021-3129", "CVE-2021-34527", "CVE-2021-40539"],
                mitre_techniques=["T1566", "T1059", "T1486", "T1041", "T1005"],
            ),
            "lockbit": ThreatActorProfile(
                name="LockBit",
                aliases=["LockBit Ransomware", "Abaddon"],
                motivation="Financial",
                target_industries=["Manufacturing", "Healthcare", "Finance"],
                known_cves=["CVE-2021-40539", "CVE-2021-2109", "CVE-2021-22911"],
                mitre_techniques=["T1566", "T1059", "T1486", "T1041", "T1005"],
            ),
            "carbanak": ThreatActorProfile(
                name="Carbanak",
                aliases=["FIN7", "Anunak"],
                motivation="Financial",
                target_industries=["Finance", "Retail", "Healthcare"],
                known_cves=["CVE-2017-0199", "CVE-2018-4878", "CVE-2021-44228"],
                mitre_techniques=["T1566", "T1566", "T1059", "T1547", "T1021", "T1005"],
            ),
            "gomorrah": ThreatActorProfile(
                name="Gomorrah",
                aliases=["Gomorrah Banking Trojan"],
                motivation="Financial",
                target_industries=["Finance", "Retail"],
                known_cves=["CVE-2017-0199", "CVE-2019-0604"],
                mitre_techniques=["T1566", "T1566", "T1059", "T1005", "T1041"],
            ),
            "silk_spider": ThreatActorProfile(
                name="Silk Spider",
                aliases=["Silk Spider", "Chinese Threat Actor"],
                motivation="Financial, Espionage",
                target_industries=["Government", "Technology", "Finance"],
                known_cves=["CVE-2021-44228", "CVE-2019-0604"],
                mitre_techniques=["T1190", "T1059", "T1547", "T1021", "T1041"],
            ),
        }
