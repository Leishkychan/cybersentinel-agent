"""Threat Model Agent — MITRE ATT&CK mapping and attack path analysis.

Scope: Analytical only. Maps findings to adversary behavior, identifies
       detection gaps, builds attack paths. Produces intelligence, not actions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
from cybersentinel.agents.base import BaseAgent
from cybersentinel.models.finding import Finding, Severity


# ============================================================================
# MITRE ATT&CK TECHNIQUE DATABASE
# ============================================================================

@dataclass
class ATTCKTechnique:
    """Represents a single MITRE ATT&CK technique."""
    technique_id: str  # e.g., "T1190"
    name: str
    tactic: str  # One of the 14 tactics
    description: str
    detection_data_sources: list[str]  # Data sources that can detect this
    mitigations: list[str]  # Mitigation strategies
    cwes: list[str]  # Associated CWE IDs
    platforms: list[str]  # Affected platforms (Windows, Linux, macOS, etc.)


class ATTCKDatabase:
    """Static database of MITRE ATT&CK techniques (v14 tactics)."""

    # The 14 tactics in ATT&CK v13+
    TACTICS = [
        "reconnaissance",
        "resource_development",
        "initial_access",
        "execution",
        "persistence",
        "privilege_escalation",
        "defense_evasion",
        "credential_access",
        "discovery",
        "lateral_movement",
        "collection",
        "command_and_control",
        "exfiltration",
        "impact",
    ]

    def __init__(self):
        """Build the technique database."""
        self.techniques: dict[str, ATTCKTechnique] = {}
        self._populate_database()

    def _populate_database(self):
        """Populate with 30+ techniques covering all 14 tactics."""
        techniques = [
            # Reconnaissance
            ATTCKTechnique(
                "T1592",
                "Gather Victim Host Information",
                "reconnaissance",
                "Adversary gathers information about victim systems (OS, hardware).",
                ["DNS records", "WHOIS", "Network traffic"],
                ["Implement network segmentation", "Monitor DNS queries"],
                ["CWE-200"],
                ["Windows", "Linux", "macOS"],
            ),
            ATTCKTechnique(
                "T1589",
                "Gather Victim Identity Information",
                "reconnaissance",
                "Adversary collects email addresses, names, job titles.",
                ["Social media monitoring", "Email logs"],
                ["Implement OSINT countermeasures"],
                ["CWE-200"],
                ["Windows", "Linux", "macOS"],
            ),
            ATTCKTechnique(
                "T1590",
                "Gather Victim Network Information",
                "reconnaissance",
                "Adversary enumerates network topology, IP ranges, DNS records.",
                ["Network traffic", "DNS logs"],
                ["Implement DNS security"],
                ["CWE-200"],
                ["Windows", "Linux", "macOS"],
            ),

            # Resource Development
            ATTCKTechnique(
                "T1583",
                "Acquire Infrastructure",
                "resource_development",
                "Adversary obtains servers, domains, or other infrastructure.",
                ["WHOIS records", "DNS registration logs"],
                ["Monitor domain registrations"],
                ["CWE-200"],
                ["Windows", "Linux", "macOS"],
            ),
            ATTCKTechnique(
                "T1586",
                "Compromise Accounts",
                "resource_development",
                "Adversary compromises existing accounts for staging.",
                ["Email security logs", "Login anomalies"],
                ["Enable MFA", "Monitor account logins"],
                ["CWE-522"],
                ["Windows", "Linux", "macOS"],
            ),
            ATTCKTechnique(
                "T1587",
                "Develop Capabilities",
                "resource_development",
                "Adversary creates malware, exploit code, or tools.",
                ["File monitoring", "Code analysis"],
                ["Monitor development tools"],
                ["CWE-94"],
                ["Windows", "Linux", "macOS"],
            ),

            # Initial Access
            ATTCKTechnique(
                "T1190",
                "Exploit Public-Facing Application",
                "initial_access",
                "Adversary exploits vulnerability in web/network application.",
                ["Web application firewall logs", "Vulnerability scanners"],
                ["Apply security patches", "WAF rules"],
                ["CWE-20", "CWE-78", "CWE-89"],
                ["Windows", "Linux"],
            ),
            ATTCKTechnique(
                "T1133",
                "External Remote Services",
                "initial_access",
                "Adversary uses VPN, RDP, or other remote access services.",
                ["VPN logs", "RDP logs", "MFA failures"],
                ["Enforce MFA", "Monitor remote access", "Disable unused services"],
                ["CWE-287"],
                ["Windows", "Linux", "macOS"],
            ),
            ATTCKTechnique(
                "T1200",
                "Hardware Additions",
                "initial_access",
                "Adversary introduces physical hardware (USB, network tap).",
                ["USB audit logs", "Network monitoring"],
                ["Disable USB ports", "Physical security controls"],
                ["CWE-434"],
                ["Windows", "Linux", "macOS"],
            ),
            ATTCKTechnique(
                "T1199",
                "Trusted Relationship",
                "initial_access",
                "Adversary exploits trusted third-party connection.",
                ["Network logs", "Third-party access logs"],
                ["Vendor risk management", "Network segmentation"],
                ["CWE-346"],
                ["Windows", "Linux", "macOS"],
            ),
            ATTCKTechnique(
                "T1193",
                "Spearphishing Attachment",
                "initial_access",
                "Adversary sends phishing email with malicious attachment.",
                ["Email logs", "File scanning", "User reports"],
                ["Email filtering", "User training"],
                ["CWE-434"],
                ["Windows", "Linux", "macOS"],
            ),

            # Execution
            ATTCKTechnique(
                "T1059",
                "Command and Scripting Interpreter",
                "execution",
                "Adversary executes commands via shell, PowerShell, etc.",
                ["Process monitoring", "Command-line logging"],
                ["Disable scripting", "Logging and monitoring"],
                ["CWE-94"],
                ["Windows", "Linux", "macOS"],
            ),
            ATTCKTechnique(
                "T1203",
                "Exploitation for Client Execution",
                "execution",
                "Adversary exploits vulnerability in client software.",
                ["Vulnerability scanners", "Process memory analysis"],
                ["Apply patches", "Update software"],
                ["CWE-20"],
                ["Windows", "Linux", "macOS"],
            ),
            ATTCKTechnique(
                "T1559",
                "Inter-Process Communication",
                "execution",
                "Adversary abuses IPC mechanisms (COM, RPC) for execution.",
                ["API monitoring", "Process hooking"],
                ["Disable IPC if unused", "Monitor COM registration"],
                ["CWE-426"],
                ["Windows"],
            ),

            # Persistence
            ATTCKTechnique(
                "T1098",
                "Account Manipulation",
                "persistence",
                "Adversary creates or modifies accounts for persistence.",
                ["Account audit logs", "Active Directory logs"],
                ["Monitor account creation", "Enforce account policies"],
                ["CWE-522"],
                ["Windows", "Linux", "macOS"],
            ),
            ATTCKTechnique(
                "T1547",
                "Boot or Logon Autostart Execution",
                "persistence",
                "Adversary configures malware to run at boot/logon.",
                ["Registry monitoring", "Autostart file monitoring"],
                ["Monitor Run/RunOnce keys", "Disable autostart if possible"],
                ["CWE-426"],
                ["Windows"],
            ),
            ATTCKTechnique(
                "T1137",
                "Office Application Startup",
                "persistence",
                "Adversary uses Office macros or add-ins for persistence.",
                ["Office file monitoring", "Macro scanning"],
                ["Disable macros", "Macro whitelisting"],
                ["CWE-94"],
                ["Windows", "macOS"],
            ),
            ATTCKTechnique(
                "T1547",
                "Browser Extensions",
                "persistence",
                "Adversary installs malicious browser extension.",
                ["Browser extension logs", "Extension auditing"],
                ["Manage extension policies", "Monitor extensions"],
                ["CWE-426"],
                ["Windows", "Linux", "macOS"],
            ),
            ATTCKTechnique(
                "T1136",
                "Create Account",
                "persistence",
                "Adversary creates new accounts for persistent access.",
                ["Account creation logs", "AD logs"],
                ["Monitor account creation", "Restrict admin rights"],
                ["CWE-522"],
                ["Windows", "Linux", "macOS"],
            ),

            # Privilege Escalation
            ATTCKTechnique(
                "T1548",
                "Abuse Elevation Control Mechanism",
                "privilege_escalation",
                "Adversary bypasses UAC or sudo restrictions.",
                ["Process monitoring", "Token impersonation logs"],
                ["Enable UAC", "Monitor privilege escalation attempts"],
                ["CWE-250"],
                ["Windows", "Linux", "macOS"],
            ),
            ATTCKTechnique(
                "T1134",
                "Access Token Manipulation",
                "privilege_escalation",
                "Adversary duplicates or steals access tokens.",
                ["Token audit logs", "Process memory analysis"],
                ["Enable token object audit", "Monitor token creation"],
                ["CWE-672"],
                ["Windows"],
            ),
            ATTCKTechnique(
                "T1547",
                "Exploitation for Privilege Escalation",
                "privilege_escalation",
                "Adversary exploits kernel vulnerability for privilege gain.",
                ["Vulnerability scanners", "Kernel audit logs"],
                ["Apply kernel patches", "Monitor for privilege changes"],
                ["CWE-20", "CWE-119"],
                ["Windows", "Linux"],
            ),

            # Defense Evasion
            ATTCKTechnique(
                "T1548",
                "Masquerading",
                "defense_evasion",
                "Adversary impersonates legitimate file/process names.",
                ["File integrity monitoring", "Process baselining"],
                ["Monitor file/process names", "Code signing validation"],
                ["CWE-427"],
                ["Windows", "Linux", "macOS"],
            ),
            ATTCKTechnique(
                "T1562",
                "Impair Defenses",
                "defense_evasion",
                "Adversary disables logging, AV, or firewalls.",
                ["Event log monitoring", "EDR alerts"],
                ["Centralized logging", "Immutable logs"],
                ["CWE-693"],
                ["Windows", "Linux", "macOS"],
            ),
            ATTCKTechnique(
                "T1140",
                "Deobfuscate/Decode Files or Information",
                "defense_evasion",
                "Adversary decodes obfuscated payloads or scripts.",
                ["Memory scanning", "Behavioral analysis"],
                ["Monitor deobfuscation tools"],
                ["CWE-94"],
                ["Windows", "Linux", "macOS"],
            ),

            # Credential Access
            ATTCKTechnique(
                "T1110",
                "Brute Force",
                "credential_access",
                "Adversary attempts repeated password guesses.",
                ["Login failure logs", "IDS/IPS", "Failed auth monitoring"],
                ["Enforce account lockout", "MFA"],
                ["CWE-307"],
                ["Windows", "Linux", "macOS"],
            ),
            ATTCKTechnique(
                "T1187",
                "Forced Authentication",
                "credential_access",
                "Adversary forces target to authenticate to attacker-controlled resource.",
                ["Network traffic analysis", "SMB logs"],
                ["Disable NTLM", "Monitor authentication attempts"],
                ["CWE-287"],
                ["Windows"],
            ),
            ATTCKTechnique(
                "T1056",
                "Input Capture",
                "credential_access",
                "Adversary captures keystrokes or clipboard.",
                ["API monitoring", "Clipboard monitoring"],
                ["Monitor input capture APIs"],
                ["CWE-636"],
                ["Windows", "Linux", "macOS"],
            ),
            ATTCKTechnique(
                "T1040",
                "Network Sniffing",
                "credential_access",
                "Adversary captures credentials from network traffic.",
                ["Network monitoring", "Encrypted traffic validation"],
                ["Enforce encryption", "Monitor promiscuous mode"],
                ["CWE-311"],
                ["Windows", "Linux", "macOS"],
            ),

            # Discovery
            ATTCKTechnique(
                "T1087",
                "Account Discovery",
                "discovery",
                "Adversary enumerates local or domain accounts.",
                ["Command-line logging", "Process monitoring"],
                ["Monitor enumeration commands"],
                ["CWE-200"],
                ["Windows", "Linux", "macOS"],
            ),
            ATTCKTechnique(
                "T1526",
                "Cloud Service Discovery",
                "discovery",
                "Adversary enumerates cloud services and configurations.",
                ["Cloud API logs", "Metadata service access"],
                ["Restrict metadata service", "Monitor API calls"],
                ["CWE-200"],
                ["Windows", "Linux", "macOS"],
            ),
            ATTCKTechnique(
                "T1538",
                "Cloud Service Enumeration",
                "discovery",
                "Adversary enumerates cloud storage buckets and permissions.",
                ["Cloud logs", "S3 bucket audits"],
                ["Restrict permissions", "Monitor enumeration"],
                ["CWE-200"],
                ["Windows", "Linux", "macOS"],
            ),

            # Lateral Movement
            ATTCKTechnique(
                "T1570",
                "Lateral Tool Transfer",
                "lateral_movement",
                "Adversary transfers tools between systems.",
                ["Network monitoring", "File transfer logs"],
                ["Monitor file transfers", "Network segmentation"],
                ["CWE-434"],
                ["Windows", "Linux", "macOS"],
            ),
            ATTCKTechnique(
                "T1021",
                "Remote Services",
                "lateral_movement",
                "Adversary uses RDP, SSH, or SMB for lateral movement.",
                ["RDP logs", "SSH logs", "SMB logs"],
                ["Restrict lateral access", "Monitor remote sessions"],
                ["CWE-287"],
                ["Windows", "Linux", "macOS"],
            ),

            # Collection
            ATTCKTechnique(
                "T1123",
                "Audio Capture",
                "collection",
                "Adversary captures audio from microphone.",
                ["Process monitoring", "Device access logs"],
                ["Monitor microphone access"],
                ["CWE-636"],
                ["Windows", "Linux", "macOS"],
            ),
            ATTCKTechnique(
                "T1119",
                "Automated Exfiltration",
                "collection",
                "Adversary automatically collects and exfiltrates data.",
                ["Network monitoring", "Data loss prevention"],
                ["DLP tools", "Network monitoring"],
                ["CWE-200"],
                ["Windows", "Linux", "macOS"],
            ),
            ATTCKTechnique(
                "T1557",
                "Man-in-the-Middle",
                "collection",
                "Adversary intercepts and modifies network traffic.",
                ["Network traffic analysis", "Certificate monitoring"],
                ["Enforce encryption", "Monitor certificates"],
                ["CWE-295"],
                ["Windows", "Linux", "macOS"],
            ),

            # Command and Control
            ATTCKTechnique(
                "T1071",
                "Application Layer Protocol",
                "command_and_control",
                "Adversary uses HTTP, DNS, or SMTP for C2.",
                ["Network monitoring", "Proxy logs"],
                ["Proxy filtering", "Network monitoring"],
                ["CWE-200"],
                ["Windows", "Linux", "macOS"],
            ),
            ATTCKTechnique(
                "T1092",
                "Communication Through Removable Media",
                "command_and_control",
                "Adversary uses USB or external storage for C2.",
                ["USB monitoring", "File monitoring"],
                ["Disable USB", "Monitor file transfers"],
                ["CWE-200"],
                ["Windows", "Linux", "macOS"],
            ),

            # Exfiltration
            ATTCKTechnique(
                "T1030",
                "Data Transfer Size Limits",
                "exfiltration",
                "Adversary fragments data to avoid DLP detection.",
                ["DLP monitoring", "Network monitoring"],
                ["DLP rules", "Monitor data transfers"],
                ["CWE-200"],
                ["Windows", "Linux", "macOS"],
            ),
            ATTCKTechnique(
                "T1041",
                "Exfiltration Over C2 Channel",
                "exfiltration",
                "Adversary exfiltrates data over existing C2 channel.",
                ["Network monitoring", "DLP"],
                ["Network monitoring", "DLP tools"],
                ["CWE-200"],
                ["Windows", "Linux", "macOS"],
            ),

            # Impact
            ATTCKTechnique(
                "T1531",
                "Account Access Removal",
                "impact",
                "Adversary locks out or disables user accounts.",
                ["Account audit logs"],
                ["Account recovery procedures"],
                ["CWE-522"],
                ["Windows", "Linux", "macOS"],
            ),
            ATTCKTechnique(
                "T1485",
                "Data Destruction",
                "impact",
                "Adversary destroys data or systems.",
                ["File deletion logs", "System logs"],
                ["Backups", "Data recovery procedures"],
                ["CWE-400"],
                ["Windows", "Linux", "macOS"],
            ),
            ATTCKTechnique(
                "T1561",
                "Disk Wipe",
                "impact",
                "Adversary wipes disk to destroy evidence.",
                ["Disk activity logs"],
                ["Backups", "Immutable logs"],
                ["CWE-400"],
                ["Windows", "Linux"],
            ),
            ATTCKTechnique(
                "T1491",
                "Defacement",
                "impact",
                "Adversary modifies web content.",
                ["Web server logs", "File integrity monitoring"],
                ["Web server hardening", "FIM"],
                ["CWE-434"],
                ["Windows", "Linux"],
            ),
        ]
        for tech in techniques:
            self.techniques[tech.technique_id] = tech

    def get_technique(self, technique_id: str) -> Optional[ATTCKTechnique]:
        """Retrieve a technique by ID."""
        return self.techniques.get(technique_id)

    def get_by_tactic(self, tactic: str) -> list[ATTCKTechnique]:
        """Get all techniques for a given tactic."""
        return [t for t in self.techniques.values() if t.tactic == tactic]

    def get_all(self) -> dict[str, ATTCKTechnique]:
        """Get all techniques."""
        return self.techniques


# ============================================================================
# ATTACK CHAIN PATTERNS
# ============================================================================

@dataclass
class AttackChain:
    """Represents a sequence of techniques that form an attack pattern."""
    name: str
    description: str
    techniques: list[str]  # Ordered sequence of technique IDs
    kill_chain_phases: list[str]  # Mapping to kill chain phases


class AttackChainDatabase:
    """Pre-defined attack chain patterns."""

    def __init__(self):
        """Initialize attack chain patterns."""
        self.chains: list[AttackChain] = [
            AttackChain(
                "Web Shell Deployment",
                "Initial access via app exploit -> execution -> persistence",
                ["T1190", "T1059", "T1547"],
                ["initial_access", "execution", "persistence"],
            ),
            AttackChain(
                "Credential Harvesting",
                "Reconnaissance -> spearphishing -> credential access -> lateral movement",
                ["T1589", "T1193", "T1110", "T1021"],
                ["reconnaissance", "initial_access", "credential_access", "lateral_movement"],
            ),
            AttackChain(
                "Living off the Land",
                "Initial access -> defense evasion -> execution -> persistence",
                ["T1059", "T1140", "T1547", "T1098"],
                ["execution", "defense_evasion", "persistence"],
            ),
            AttackChain(
                "Privilege Escalation Chain",
                "Initial foothold -> local exploit -> privilege escalation -> persistence",
                ["T1133", "T1203", "T1548", "T1547"],
                ["initial_access", "execution", "privilege_escalation", "persistence"],
            ),
            AttackChain(
                "Data Exfiltration",
                "Discovery -> collection -> C2 channel -> exfiltration",
                ["T1087", "T1119", "T1071", "T1041"],
                ["discovery", "collection", "command_and_control", "exfiltration"],
            ),
            AttackChain(
                "Supply Chain Attack",
                "Resource development -> trusted relationship -> execution",
                ["T1587", "T1199", "T1059"],
                ["resource_development", "initial_access", "execution"],
            ),
            AttackChain(
                "Ransomware Deployment",
                "Initial access -> execution -> impact + exfiltration",
                ["T1190", "T1059", "T1485", "T1041"],
                ["initial_access", "execution", "impact", "exfiltration"],
            ),
            AttackChain(
                "Insider Threat Pattern",
                "Credential access -> discovery -> collection -> exfiltration",
                ["T1110", "T1087", "T1119", "T1041"],
                ["credential_access", "discovery", "collection", "exfiltration"],
            ),
        ]

    def find_chains(self, technique_ids: list[str]) -> list[AttackChain]:
        """Find matching attack chains given a list of techniques."""
        matched = []
        technique_set = set(technique_ids)
        for chain in self.chains:
            # Match if majority of chain techniques are present
            chain_techniques = set(chain.techniques)
            if len(chain_techniques & technique_set) >= len(chain_techniques) * 0.6:
                matched.append(chain)
        return matched


# ============================================================================
# THREAT ACTOR PROFILING
# ============================================================================

@dataclass
class ThreatActorProfile:
    """Represents a threat actor category."""
    category: str
    description: str
    typical_techniques: list[str]
    objectives: list[str]


class ThreatActorProfiler:
    """Profiles threat actors based on observed techniques."""

    def __init__(self):
        """Initialize threat actor profiles."""
        self.profiles = [
            ThreatActorProfile(
                "Nation-State (APT)",
                "Advanced Persistent Threat - high sophistication, prolonged access",
                [
                    "T1190",
                    "T1133",
                    "T1059",
                    "T1548",
                    "T1078",
                    "T1087",
                    "T1119",
                    "T1071",
                    "T1041",
                ],
                ["espionage", "disruption", "theft of state secrets"],
            ),
            ThreatActorProfile(
                "Cybercrime",
                "Financially motivated - ransomware, credential theft, fraud",
                [
                    "T1193",
                    "T1110",
                    "T1059",
                    "T1485",
                    "T1041",
                    "T1071",
                    "T1562",
                ],
                ["financial gain", "extortion", "identity theft"],
            ),
            ThreatActorProfile(
                "Insider Threat",
                "Privileged user - abuse of access for data theft or sabotage",
                [
                    "T1087",
                    "T1119",
                    "T1041",
                    "T1530",
                    "T1485",
                    "T1561",
                ],
                ["data theft", "sabotage", "competitive advantage"],
            ),
            ThreatActorProfile(
                "Hacktivist",
                "Ideologically motivated - defacement, service disruption",
                [
                    "T1190",
                    "T1491",
                    "T1561",
                    "T1485",
                    "T1071",
                ],
                ["activism", "protest", "political goals"],
            ),
            ThreatActorProfile(
                "Script Kiddie",
                "Low sophistication - uses existing tools and exploits",
                [
                    "T1190",
                    "T1193",
                    "T1110",
                    "T1491",
                ],
                ["notoriety", "disruption", "learning"],
            ),
        ]

    def profile(self, technique_ids: list[str]) -> list[tuple[ThreatActorProfile, float]]:
        """
        Profile threat actors based on observed techniques.
        Returns list of (profile, confidence_score).
        """
        technique_set = set(technique_ids)
        results = []
        for profile in self.profiles:
            profile_techniques = set(profile.typical_techniques)
            if not profile_techniques:
                continue
            overlap = len(technique_set & profile_techniques)
            confidence = overlap / len(profile_techniques)
            if confidence > 0.3:  # Only return profiles with >30% confidence
                results.append((profile, confidence))
        # Sort by confidence descending
        return sorted(results, key=lambda x: x[1], reverse=True)


# ============================================================================
# STRIDE ANALYSIS
# ============================================================================

class STRIDEAnalyzer:
    """Performs STRIDE threat modeling."""

    STRIDE_CATEGORIES = {
        "spoofing": {
            "description": "Spoofing Identity",
            "examples": ["fake credentials", "compromised accounts"],
            "techniques": ["T1098", "T1110", "T1187"],
        },
        "tampering": {
            "description": "Tampering with Data",
            "examples": ["data modification", "code injection"],
            "techniques": ["T1055", "T1140", "T1491"],
        },
        "repudiation": {
            "description": "Repudiation of Actions",
            "examples": ["lack of logging", "deleted audit trails"],
            "techniques": ["T1562", "T1070"],
        },
        "information_disclosure": {
            "description": "Information Disclosure",
            "examples": ["credential theft", "data exfiltration"],
            "techniques": ["T1040", "T1041", "T1119"],
        },
        "denial_of_service": {
            "description": "Denial of Service",
            "examples": ["resource exhaustion", "system crash"],
            "techniques": ["T1485", "T1561", "T1531"],
        },
        "elevation_of_privilege": {
            "description": "Elevation of Privilege",
            "examples": ["privilege escalation", "bypass controls"],
            "techniques": ["T1548", "T1134", "T1547"],
        },
    }

    def analyze(self, architecture: str) -> dict:
        """Perform STRIDE analysis on architecture description."""
        findings = {}
        # Basic keyword matching for demo
        arch_lower = architecture.lower()
        for category, details in self.STRIDE_CATEGORIES.items():
            score = 0
            if any(
                word in arch_lower
                for word in [
                    "authentication",
                    "credential",
                    "identity",
                    "account",
                ]
            ):
                if category in ["spoofing", "elevation_of_privilege"]:
                    score += 0.5
            if any(word in arch_lower for word in ["database", "data", "api"]):
                if category in ["tampering", "information_disclosure"]:
                    score += 0.5
            if any(word in arch_lower for word in ["network", "service", "load"]):
                if category in ["denial_of_service"]:
                    score += 0.5
            if score > 0:
                findings[category] = {
                    "description": details["description"],
                    "examples": details["examples"],
                    "techniques": details["techniques"],
                    "risk_score": min(score, 1.0),
                }
        return findings


# ============================================================================
# MAIN THREAT MODEL AGENT
# ============================================================================


class ThreatModelAgent(BaseAgent):
    """Maps findings to MITRE ATT&CK and performs threat analysis.

    For each finding from other sub-agents:
    - Maps to ATT&CK tactics and techniques
    - Identifies attack chains (how findings combine)
    - Assesses detection coverage gaps
    - Recommends detection data sources
    - Profiles likely threat actors

    Also performs standalone threat modeling:
    - STRIDE analysis
    - Attack chain identification
    - Threat actor profiling
    - Trust boundary analysis

    Input: Findings from other agents + architecture context
    Output: ATT&CK mappings, attack paths, detection gaps
    """

    name = "threat_model"
    description = "MITRE ATT&CK mapping and threat modeling"

    def __init__(self, session):
        """Initialize agent with databases."""
        super().__init__(session)
        self.attack_db = ATTCKDatabase()
        self.chain_db = AttackChainDatabase()
        self.profiler = ThreatActorProfiler()
        self.stride = STRIDEAnalyzer()

    def analyze(self, target: str, context: dict) -> list[Finding]:
        """Perform threat modeling and ATT&CK mapping.

        Args:
            target: System or architecture identifier
            context: Must include:
                - 'findings': list[Finding] (optional) — findings to map
                - 'architecture': str (optional) — system description
                - 'data_flows': str (optional) — DFD description

        Returns:
            List of threat model findings (gaps, attack paths)
        """
        self.validate(target, f"Threat modeling for {target}")
        self.log(f"Starting threat model analysis for {target}")

        findings: list[Finding] = []

        # Extract context
        input_findings = context.get("findings", [])
        architecture = context.get("architecture", "")
        data_flows = context.get("data_flows", "")

        # Convert input findings to dicts if needed
        finding_dicts = []
        for f in input_findings:
            if isinstance(f, Finding):
                finding_dicts.append(f.to_dict())
            else:
                finding_dicts.append(f)

        # Phase 1: Map findings to ATT&CK
        technique_to_findings = self._map_to_attack(finding_dicts)
        findings.extend(
            self._create_attack_mapping_findings(technique_to_findings, finding_dicts)
        )

        # Phase 2: Identify attack chains
        techniques_found = list(technique_to_findings.keys())
        if techniques_found:
            chains = self.chain_db.find_chains(techniques_found)
            findings.extend(self._create_attack_chain_findings(chains, techniques_found))

        # Phase 3: Detect detection gaps
        findings.extend(self._detect_gaps(technique_to_findings))

        # Phase 4: Profile threat actors
        if techniques_found:
            profiles = self.profiler.profile(techniques_found)
            findings.extend(self._create_profiling_findings(profiles, techniques_found))

        # Phase 5: STRIDE analysis
        if architecture:
            stride_findings = self.stride.analyze(architecture)
            findings.extend(self._create_stride_findings(stride_findings))

        self.log(f"Threat model complete: {len(findings)} findings identified")
        return findings

    def _map_to_attack(self, finding_dicts: list[dict]) -> dict[str, list[dict]]:
        """Map findings to ATT&CK techniques.

        Returns: Dict[technique_id -> list of findings]
        """
        technique_to_findings: dict[str, list[dict]] = {}

        for finding in finding_dicts:
            # If finding has explicit technique mappings, use them
            if finding.get("mitre_techniques"):
                for tech in finding.get("mitre_techniques", []):
                    if tech not in technique_to_findings:
                        technique_to_findings[tech] = []
                    technique_to_findings[tech].append(finding)
            else:
                # Heuristic: infer from description and CVE/CWE
                inferred = self._infer_techniques(finding)
                for tech in inferred:
                    if tech not in technique_to_findings:
                        technique_to_findings[tech] = []
                    technique_to_findings[tech].append(finding)

        return technique_to_findings

    def _infer_techniques(self, finding: dict) -> list[str]:
        """Infer ATT&CK techniques from finding description."""
        inferred = []
        desc = (finding.get("description", "") + finding.get("title", "")).lower()
        cwe_ids = finding.get("cwe_ids", [])

        # Simple keyword matching
        if any(word in desc for word in ["command", "script", "shell", "powershell"]):
            inferred.append("T1059")
        if any(
            word in desc
            for word in ["credential", "password", "brute", "sniff", "intercept"]
        ):
            inferred.append("T1110")
            inferred.append("T1040")
        if any(word in desc for word in ["exploit", "vulnerability", "cve"]):
            inferred.append("T1190")
            inferred.append("T1203")
        if any(word in desc for word in ["persistence", "startup", "registry", "autorun"]):
            inferred.append("T1547")
        if any(
            word in desc
            for word in [
                "privilege",
                "elevation",
                "escalation",
                "admin",
                "root",
            ]
        ):
            inferred.append("T1548")
        if any(word in desc for word in ["web", "http", "request", "response"]):
            inferred.append("T1071")
        if any(
            word in desc for word in ["exfiltration", "data transfer", "download"]
        ):
            inferred.append("T1041")
        if any(word in desc for word in ["phishing", "email", "spear"]):
            inferred.append("T1193")
        if any(word in desc for word in ["enumeration", "discovery", "reconnaissance"]):
            inferred.append("T1087")
            inferred.append("T1526")
        if any(word in desc for word in ["lateral", "movement", "remote", "rdp", "ssh"]):
            inferred.append("T1021")
        if any(word in desc for word in ["defense", "disable", "evasion", "bypass"]):
            inferred.append("T1562")
        if any(word in desc for word in ["collection", "gathering"]):
            inferred.append("T1119")

        # CWE-based inference
        if "CWE-78" in cwe_ids or "CWE-94" in cwe_ids:
            inferred.append("T1059")
        if "CWE-22" in cwe_ids:
            inferred.append("T1190")
        if "CWE-287" in cwe_ids or "CWE-307" in cwe_ids:
            inferred.append("T1110")

        return list(set(inferred))

    def _create_attack_mapping_findings(
        self, technique_to_findings: dict[str, list[dict]], all_findings: list[dict]
    ) -> list[Finding]:
        """Create findings for ATT&CK mappings."""
        findings = []

        # Create a summary finding for each technique
        for technique_id, related_findings in technique_to_findings.items():
            technique = self.attack_db.get_technique(technique_id)
            if not technique:
                continue

            related_titles = [f.get("title", "?") for f in related_findings]
            affected = list(set(f.get("affected_component", "?") for f in related_findings))

            finding = Finding(
                title=f"ATT&CK Technique {technique_id}: {technique.name}",
                severity=Severity.MEDIUM,
                description=f"{technique.description}\n\nRelated findings:\n"
                + "\n".join(f"  - {t}" for t in related_titles[:5]),
                affected_component=", ".join(affected[:3]),
                agent_source=self.name,
                mitre_tactics=[technique.tactic],
                mitre_techniques=[technique_id],
                mitre_mitigations=technique.mitigations,
                cwe_ids=technique.cwes,
                detection_guidance=f"Data sources: {', '.join(technique.detection_data_sources[:3])}",
                evidence=f"{len(related_findings)} finding(s) mapped to this technique",
                confidence="high",
            )
            findings.append(finding)

        return findings

    def _create_attack_chain_findings(
        self, chains: list[AttackChain], techniques_found: list[str]
    ) -> list[Finding]:
        """Create findings for identified attack chains."""
        findings = []

        for chain in chains:
            present_techniques = [t for t in chain.techniques if t in techniques_found]

            finding = Finding(
                title=f"Attack Chain: {chain.name}",
                severity=Severity.HIGH,
                description=f"{chain.description}\n\n"
                f"Techniques observed: {', '.join(present_techniques)}\n"
                f"Kill chain phases: {' → '.join(chain.kill_chain_phases)}",
                affected_component="System-wide attack flow",
                agent_source=self.name,
                mitre_tactics=chain.kill_chain_phases,
                mitre_techniques=present_techniques,
                detection_guidance="Monitor for sequences of these techniques. Implement cross-tactic detection rules.",
                evidence=f"{len(present_techniques)}/{len(chain.techniques)} techniques in chain detected",
                confidence="high",
            )
            findings.append(finding)

        return findings

    def _detect_gaps(self, technique_to_findings: dict[str, list[dict]]) -> list[Finding]:
        """Detect detection coverage gaps."""
        findings = []

        for technique_id, related_findings in technique_to_findings.items():
            technique = self.attack_db.get_technique(technique_id)
            if not technique:
                continue

            # Check if findings have detection guidance
            has_detection = any(
                f.get("detection_guidance") or f.get("sigma_rule")
                for f in related_findings
            )

            if not has_detection and technique.detection_data_sources:
                finding = Finding(
                    title=f"Detection Gap: {technique_id} ({technique.name})",
                    severity=Severity.MEDIUM,
                    description=f"No detection mechanisms present for {technique_id}.\n\n"
                    f"Recommended data sources:\n"
                    + "\n".join(f"  - {ds}" for ds in technique.detection_data_sources),
                    affected_component="Security monitoring",
                    agent_source=self.name,
                    mitre_techniques=[technique_id],
                    mitre_tactics=[technique.tactic],
                    detection_guidance=f"Implement monitoring for: {', '.join(technique.detection_data_sources[:3])}",
                    remediation=f"Deploy detection rules for {technique_id} using recommended data sources.",
                    evidence="No detection capability found",
                    confidence="high",
                )
                findings.append(finding)

        return findings

    def _create_profiling_findings(
        self, profiles: list[tuple[ThreatActorProfile, float]], techniques_found: list[str]
    ) -> list[Finding]:
        """Create findings for threat actor profiling."""
        findings = []

        for profile, confidence in profiles:
            finding = Finding(
                title=f"Threat Actor Profile: {profile.category}",
                severity=Severity.HIGH if confidence > 0.7 else Severity.MEDIUM,
                description=f"{profile.description}\n\n"
                f"Confidence: {confidence * 100:.0f}%\n"
                f"Typical objectives: {', '.join(profile.objectives)}\n"
                f"Matched techniques: {', '.join(techniques_found[:5])}",
                affected_component="Threat intelligence",
                agent_source=self.name,
                mitre_techniques=techniques_found,
                detection_guidance=f"Monitor for {profile.category} indicators. "
                f"Adjust detection priorities to {profile.objectives[0] if profile.objectives else 'unknown'}.",
                evidence=f"{confidence * 100:.0f}% confidence match",
                confidence="high" if confidence > 0.7 else "medium",
            )
            findings.append(finding)

        return findings

    def _create_stride_findings(self, stride_findings: dict) -> list[Finding]:
        """Create findings from STRIDE analysis."""
        findings = []

        for category, details in stride_findings.items():
            severity = Severity.HIGH if details["risk_score"] > 0.7 else Severity.MEDIUM
            finding = Finding(
                title=f"STRIDE: {details['description']}",
                severity=severity,
                description=f"Category: {category}\n\n"
                f"Examples: {', '.join(details['examples'])}\n"
                f"Risk Score: {details['risk_score']:.0%}\n"
                f"Related techniques: {', '.join(details['techniques'])}",
                affected_component="Architecture/Design",
                agent_source=self.name,
                mitre_tactics=[],
                mitre_techniques=details["techniques"],
                detection_guidance=f"Conduct STRIDE workshop for {category}. "
                f"Design mitigations for identified threats.",
                evidence=f"STRIDE analysis flagged {category}",
                confidence="medium",
            )
            findings.append(finding)

        return findings
