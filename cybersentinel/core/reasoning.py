"""Autonomous reasoning engine — the brain of CyberSentinel.

This module implements the core reasoning loop that makes CyberSentinel
autonomous: plan → execute → analyze → replan → repeat until exhausted
or a human authorization point (exploit) is reached.

The reasoning engine operates on the philosophy that deeper investigation
always reveals more attack surface. It decomposes goals into phases, executes
them in parallel where safe, analyzes findings, and continuously replans
based on what's discovered.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class PhaseStatus(str, Enum):
    """Status of a phase in the reasoning loop."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    BLOCKED = "blocked"


@dataclass
class Phase:
    """A single phase in the execution plan.

    Phases are the atomic units of work in the reasoning loop. Each phase
    defines a set of agents to run, dependencies, and depth tracking.
    """
    name: str
    description: str
    agents_to_run: list[str]
    depends_on: list[str] = field(default_factory=list)
    depth: int = 0
    status: PhaseStatus = PhaseStatus.PENDING
    findings: list[dict] = field(default_factory=list)
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    execution_log: list[str] = field(default_factory=list)

    def mark_running(self) -> None:
        """Mark this phase as running."""
        self.status = PhaseStatus.RUNNING
        self.started_at = datetime.now(timezone.utc).isoformat()

    def mark_complete(self) -> None:
        """Mark this phase as complete."""
        self.status = PhaseStatus.COMPLETE
        self.completed_at = datetime.now(timezone.utc).isoformat()

    def add_finding(self, finding: dict) -> None:
        """Add a finding discovered during this phase."""
        self.findings.append(finding)

    def add_log(self, entry: str) -> None:
        """Add an entry to the execution log."""
        timestamp = datetime.now(timezone.utc).isoformat()
        self.execution_log.append(f"[{timestamp}] {entry}")


@dataclass
class ExploitBriefing:
    """Complete briefing for an exploitable finding.

    When CyberSentinel discovers an exploitable vulnerability, it generates
    a full briefing with risk assessment, impact analysis, and abort conditions
    before stopping for human authorization. It NEVER exploits autonomously.
    """
    finding_id: str
    finding_title: str
    finding_severity: str
    affected_component: str
    cve_ids: list[str]
    cvss_score: Optional[float]

    exploit_steps: list[str]
    tools_needed: list[str]
    stealth_rating: float  # 0-1, higher = stealthier

    detection_probability_before: float  # 0-1, probability of detection before exploit
    detection_probability_during: float  # 0-1, probability of detection during exploit
    detection_probability_after: float   # 0-1, probability of detection after exploit

    blast_radius: str  # "localized", "service", "infrastructure", "network"
    reversibility: str  # "reversible", "partially_reversible", "irreversible"
    abort_conditions: list[str]

    risk_rating: str  # "critical", "high", "medium", "low"
    human_authorization_required: bool = True

    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        """Serialize for logging and human review."""
        return {
            "finding_id": self.finding_id,
            "finding_title": self.finding_title,
            "finding_severity": self.finding_severity,
            "affected_component": self.affected_component,
            "cve_ids": self.cve_ids,
            "cvss_score": self.cvss_score,
            "exploit_steps": self.exploit_steps,
            "tools_needed": self.tools_needed,
            "stealth_rating": self.stealth_rating,
            "detection_probability": {
                "before": self.detection_probability_before,
                "during": self.detection_probability_during,
                "after": self.detection_probability_after,
            },
            "blast_radius": self.blast_radius,
            "reversibility": self.reversibility,
            "abort_conditions": self.abort_conditions,
            "risk_rating": self.risk_rating,
            "human_authorization_required": self.human_authorization_required,
            "created_at": self.created_at,
        }


@dataclass
class ReasoningResult:
    """Final result of the reasoning loop execution."""
    goal: str
    phases_executed: list[Phase]
    total_findings: int
    exploit_briefings: list[ExploitBriefing]
    reasoning_log: list[str]
    depth_reached: int
    status: str  # "exhausted", "depth_limit", "exploitation_required"
    completed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def add_log_entry(self, entry: str) -> None:
        """Add an entry to the reasoning log."""
        timestamp = datetime.now(timezone.utc).isoformat()
        log_entry = f"[{timestamp}] {entry}"
        self.reasoning_log.append(log_entry)
        logger.info(entry)

    def to_dict(self) -> dict:
        """Serialize for reporting."""
        return {
            "goal": self.goal,
            "phases_executed": len(self.phases_executed),
            "total_findings": self.total_findings,
            "exploit_briefings": len(self.exploit_briefings),
            "depth_reached": self.depth_reached,
            "status": self.status,
            "reasoning_log": self.reasoning_log,
            "completed_at": self.completed_at,
        }


class ReasoningEngine:
    """Autonomous reasoning engine for CyberSentinel.

    This engine implements the core loop:
    1. Plan: Decompose goal into phases
    2. Execute: Run agents in phases
    3. Analyze: Extract insights from findings
    4. Replan: Generate new phases based on discoveries
    5. Repeat until exhausted or exploitation is needed

    The engine is "greedy" for discovery — it will continue to plan deeper
    investigation until:
    - All attack surface has been exhausted (no new findings)
    - Depth limit is reached
    - An exploitable vulnerability is found (stops for human auth)
    """

    def __init__(self, session, config):
        """Initialize the reasoning engine.

        Args:
            session: CyberSentinel session object
            config: SentinelConfig object with enabled models and scan defaults
        """
        self.session = session
        self.config = config
        self.logger = logging.getLogger(__name__)

    def plan(self, goal: str, context: dict) -> list[Phase]:
        """Decompose a goal into ordered phases.

        This is the initial planning step. It takes a high-level goal
        (e.g., "find vulnerabilities in target.com") and breaks it down
        into specific, executable phases with clear dependencies and depth.

        Args:
            goal: High-level objective (e.g., "find vulnerabilities in target.com")
            context: Additional context (target, scope, user preferences)

        Returns:
            List of Phase objects in dependency order
        """
        phases = []

        # Phase 1: Reconnaissance — basic system discovery
        recon_phase = Phase(
            name="reconnaissance",
            description="Initial passive information gathering",
            agents_to_run=["dns_enum", "whois", "shodan_query", "certificate_transparency"],
            depends_on=[],
            depth=1,
        )
        phases.append(recon_phase)

        # Phase 2: Network Scanning — port and service discovery
        network_phase = Phase(
            name="network_scanning",
            description="Active network scanning for open ports and services",
            agents_to_run=["nmap_scanner", "service_detector"],
            depends_on=["reconnaissance"],
            depth=2,
        )
        phases.append(network_phase)

        # Phase 3: Vulnerability Scanning — known CVE detection
        vuln_phase = Phase(
            name="vulnerability_scanning",
            description="Scan for known vulnerabilities in detected services",
            agents_to_run=["nuclei_scanner", "cve_scanner", "config_auditor"],
            depends_on=["network_scanning"],
            depth=3,
        )
        phases.append(vuln_phase)

        # Phase 4: Application Scanning — web app specific checks
        app_phase = Phase(
            name="application_scanning",
            description="Application-level vulnerability assessment",
            agents_to_run=["web_app_scanner", "jwt_analyzer", "api_fuzzer"],
            depends_on=["network_scanning"],
            depth=3,
        )
        phases.append(app_phase)

        # Phase 5: Credential Analysis — check for exposed secrets
        cred_phase = Phase(
            name="credential_analysis",
            description="Scan for exposed credentials and secrets",
            agents_to_run=["secret_scanner", "git_recon", "env_analyzer"],
            depends_on=["reconnaissance"],
            depth=2,
        )
        phases.append(cred_phase)

        return phases

    def execute_loop(self, goal: str, max_depth: int = 5) -> ReasoningResult:
        """Execute the full autonomous reasoning loop.

        This is the main entry point. It orchestrates the entire process:
        1. Plan initial phases
        2. Execute phases
        3. Analyze findings and replan
        4. Repeat until exhausted or exploitation needed

        Args:
            goal: High-level goal (e.g., "find vulnerabilities in target.com")
            max_depth: Maximum depth to reach (default 5)

        Returns:
            ReasoningResult with all findings and exploit briefings
        """
        result = ReasoningResult(
            goal=goal,
            phases_executed=[],
            total_findings=0,
            exploit_briefings=[],
            reasoning_log=[],
            depth_reached=0,
            status="",
        )

        result.add_log_entry(f"Starting reasoning loop: {goal}")

        # Initial context
        context = {"target": goal}

        # Phase 1: Initial planning
        plan = self.plan(goal, context)
        result.add_log_entry(f"Created initial plan with {len(plan)} phases")

        current_depth = 1
        phases_to_execute = plan[:]
        executed_phases = {}

        # Main loop
        while current_depth <= max_depth and phases_to_execute:
            result.add_log_entry(f"Depth {current_depth}: {len(phases_to_execute)} phases ready")

            # Check dependencies — only execute phases where all deps are done
            executable = []
            for phase in phases_to_execute:
                if all(dep in executed_phases for dep in phase.depends_on):
                    executable.append(phase)
                else:
                    result.add_log_entry(
                        f"Phase '{phase.name}' blocked (waiting for: {[d for d in phase.depends_on if d not in executed_phases]})"
                    )

            if not executable:
                result.add_log_entry("No more executable phases, ending loop")
                break

            # Execute executable phases
            for phase in executable:
                phase.mark_running()
                result.add_log_entry(f"Executing phase: {phase.name}")

                # Simulate agent execution (in real system, this calls actual agents)
                findings = self._simulate_agent_execution(phase)
                phase.findings = findings
                phase.mark_complete()

                result.total_findings += len(findings)
                result.add_log_entry(f"Phase '{phase.name}' complete: {len(findings)} findings")

                # Check for exploitable findings
                for finding in findings:
                    if self._is_exploitable(finding):
                        briefing = self.create_exploit_briefing(finding)
                        result.exploit_briefings.append(briefing)
                        result.add_log_entry(
                            f"EXPLOITATION REQUIRED: {finding.get('title', 'Unknown')} — stopping for human authorization"
                        )
                        result.status = "exploitation_required"
                        result.depth_reached = current_depth
                        result.phases_executed.append(phase)
                        return result

                executed_phases[phase.name] = phase
                phases_to_execute.remove(phase)
                result.phases_executed.append(phase)

            # Analyze findings and replan
            new_phases = self.analyze_results(
                [f for p in result.phases_executed for f in p.findings],
                result.phases_executed[-1] if result.phases_executed else None,
            )

            if new_phases:
                result.add_log_entry(f"Replanning: discovered {len(new_phases)} new phases to explore")
                phases_to_execute.extend(new_phases)
            else:
                result.add_log_entry("No new attack surface discovered, ending exploration")
                break

            # Check if we should go deeper
            current_findings = [f for p in result.phases_executed for f in p.findings]
            if not self.should_go_deeper(current_findings, current_depth):
                result.add_log_entry("Depth check: no new findings from last depth, stopping")
                break

            current_depth += 1

        result.depth_reached = current_depth
        result.status = "exhausted" if not result.exploit_briefings else "exploitation_required"
        result.add_log_entry(
            f"Reasoning loop complete: {result.total_findings} findings, "
            f"{len(result.exploit_briefings)} exploitable, depth {result.depth_reached}"
        )

        return result

    def analyze_results(self, findings: list[dict], current_phase: Optional[Phase]) -> list[Phase]:
        """Analyze findings and generate new phases for deeper investigation.

        This is where the AI "looks at what we found" and decides what to probe
        next. For example:
        - Found SSRF vulnerability? Plan internal network probe
        - Found weak authentication? Plan brute-force/bypass attempts
        - Found misconfigured cloud storage? Plan data extraction

        Args:
            findings: List of findings from previous phases
            current_phase: The last executed phase (for context)

        Returns:
            List of new Phase objects to add to the execution plan
        """
        new_phases = []

        if not findings:
            return new_phases

        # Analyze finding types and generate appropriate phases
        finding_types = set(f.get("type", "unknown") for f in findings)

        # If SSRF found, plan internal network probe
        if any("ssrf" in str(f.get("title", "")).lower() for f in findings):
            new_phases.append(
                Phase(
                    name="internal_network_probe",
                    description="Probe internal network via SSRF vulnerability",
                    agents_to_run=["ssrf_enumerator", "internal_port_scanner"],
                    depends_on=["application_scanning"],
                    depth=(current_phase.depth + 1) if current_phase else 3,
                )
            )

        # If SQL injection found, plan database enumeration
        if any("sql" in str(f.get("title", "")).lower() for f in findings):
            new_phases.append(
                Phase(
                    name="database_enumeration",
                    description="Enumerate database structure and contents",
                    agents_to_run=["sql_enumerator", "schema_mapper"],
                    depends_on=["application_scanning"],
                    depth=(current_phase.depth + 1) if current_phase else 3,
                )
            )

        # If authentication weakness found, plan privilege escalation
        if any("auth" in str(f.get("title", "")).lower() for f in findings):
            new_phases.append(
                Phase(
                    name="privilege_escalation",
                    description="Attempt privilege escalation via weak authentication",
                    agents_to_run=["priv_esc_detector", "role_mapper"],
                    depends_on=["application_scanning"],
                    depth=(current_phase.depth + 1) if current_phase else 3,
                )
            )

        # If RCE potential found, plan code execution
        if any("rce" in str(f.get("title", "")).lower() or "remote code" in str(f.get("title", "")).lower() for f in findings):
            new_phases.append(
                Phase(
                    name="code_execution_analysis",
                    description="Analyze remote code execution potential",
                    agents_to_run=["payload_generator", "execution_simulator"],
                    depends_on=["vulnerability_scanning"],
                    depth=(current_phase.depth + 1) if current_phase else 3,
                )
            )

        # If cloud resource found, plan cloud-specific enumeration
        if any("s3" in str(f.get("title", "")).lower() or "bucket" in str(f.get("title", "")).lower() for f in findings):
            new_phases.append(
                Phase(
                    name="cloud_enumeration",
                    description="Enumerate cloud resources and permissions",
                    agents_to_run=["cloud_bucket_scanner", "iam_mapper"],
                    depends_on=["reconnaissance"],
                    depth=(current_phase.depth + 1) if current_phase else 2,
                )
            )

        return new_phases

    def should_go_deeper(self, findings: list[dict], depth: int) -> bool:
        """Decide if there's more to discover at the next depth level.

        This check prevents infinite loops. If the last depth level didn't
        reveal anything new, there's probably nothing more to find.

        Args:
            findings: All findings so far
            depth: Current depth

        Returns:
            True if we should continue to the next depth
        """
        if depth >= 5:  # Hard limit
            return False

        if not findings:  # Nothing found yet, always go deeper
            return True

        # Simple heuristic: if we have findings but no recent exploitable ones,
        # it's worth going one more level deep
        exploitable = [f for f in findings if self._is_exploitable(f)]
        if exploitable:
            # We have exploitable findings — should stop and brief human
            return False

        # We have findings but nothing exploitable yet — go deeper
        return True

    def create_exploit_briefing(self, finding: dict) -> ExploitBriefing:
        """Create a complete exploit briefing for a finding.

        When an exploitable vulnerability is discovered, this generates
        a full risk assessment and exploit briefing WITHOUT executing it.
        The system stops and waits for human authorization.

        Args:
            finding: The finding dict

        Returns:
            ExploitBriefing object ready for human review
        """
        # Extract finding details
        finding_id = finding.get("id", "unknown")
        title = finding.get("title", "Unknown Vulnerability")
        severity = finding.get("severity", "unknown")
        component = finding.get("affected_component", "unknown")
        cve_ids = finding.get("cve_ids", [])
        cvss_score = finding.get("cvss_score")

        # Generate exploit steps (in real system, AI models would generate these)
        exploit_steps = self._generate_exploit_steps(finding)

        # Determine tools needed
        tools_needed = self._determine_tools_needed(finding)

        # Assess stealth
        stealth_rating = self._assess_stealth(finding)

        # Assess detection probability
        detection_before = self._assess_detection_before(finding)
        detection_during = self._assess_detection_during(finding)
        detection_after = self._assess_detection_after(finding)

        # Assess blast radius
        blast_radius = self._assess_blast_radius(finding)

        # Assess reversibility
        reversibility = self._assess_reversibility(finding)

        # Generate abort conditions
        abort_conditions = self._generate_abort_conditions(finding)

        # Overall risk rating
        risk_rating = self._calculate_risk_rating(
            severity, detection_during, blast_radius, reversibility
        )

        briefing = ExploitBriefing(
            finding_id=finding_id,
            finding_title=title,
            finding_severity=severity,
            affected_component=component,
            cve_ids=cve_ids,
            cvss_score=cvss_score,
            exploit_steps=exploit_steps,
            tools_needed=tools_needed,
            stealth_rating=stealth_rating,
            detection_probability_before=detection_before,
            detection_probability_during=detection_during,
            detection_probability_after=detection_after,
            blast_radius=blast_radius,
            reversibility=reversibility,
            abort_conditions=abort_conditions,
            risk_rating=risk_rating,
            human_authorization_required=True,
        )

        return briefing

    # --- Helper methods for exploit briefing generation ---

    def _is_exploitable(self, finding: dict) -> bool:
        """Determine if a finding is exploitable (not just informational)."""
        severity = finding.get("severity", "").lower()
        title = finding.get("title", "").lower()

        # Informational and low findings are rarely exploitable
        if severity in ["informational", "info", "low"]:
            return False

        # Known exploitable patterns
        exploitable_keywords = [
            "rce", "remote code execution",
            "sql injection", "sqli",
            "command injection",
            "ssrf", "server-side request forgery",
            "authentication bypass",
            "privilege escalation",
            "deserialization",
            "xxe", "xml external entity",
        ]

        return any(keyword in title for keyword in exploitable_keywords)

    def _generate_exploit_steps(self, finding: dict) -> list[str]:
        """Generate step-by-step exploit instructions."""
        title = finding.get("title", "").lower()
        component = finding.get("affected_component", "")

        steps = [
            "1. Verify the vulnerability exists by reproducing the detection",
            "2. Prepare payload based on vulnerability type",
            "3. Execute payload with monitoring in place",
            "4. Collect evidence of successful exploitation",
            "5. Document impact and access gained",
        ]

        if "sql" in title:
            steps = [
                "1. Identify injectable parameter",
                "2. Test for SQL injection using basic payloads",
                "3. Determine database type and version",
                "4. Extract database contents using appropriate queries",
                "5. Document findings and remediate",
            ]
        elif "rce" in title or "remote code" in title:
            steps = [
                "1. Identify code execution vector",
                "2. Prepare proof-of-concept payload",
                "3. Execute payload in isolated environment",
                "4. Verify command execution",
                "5. Document and remediate",
            ]
        elif "ssrf" in title:
            steps = [
                "1. Identify SSRF parameter",
                "2. Test with known internal IPs/ranges",
                "3. Enumerate internal services",
                "4. Document findings and remediate",
            ]

        return steps

    def _determine_tools_needed(self, finding: dict) -> list[str]:
        """Determine which tools are needed to exploit this finding."""
        title = finding.get("title", "").lower()
        tools = []

        if "sql" in title:
            tools.extend(["sqlmap", "burp-suite"])
        elif "rce" in title or "remote code" in title:
            tools.extend(["metasploit", "custom-payload-gen"])
        elif "ssrf" in title:
            tools.extend(["burp-suite", "curl"])
        elif "auth" in title:
            tools.extend(["john", "hashcat", "burp-suite"])

        if not tools:
            tools = ["burp-suite", "custom-tools"]

        return tools

    def _assess_stealth(self, finding: dict) -> float:
        """Assess stealth rating (0-1, higher = stealthier)."""
        title = finding.get("title", "").lower()

        # Some exploits are inherently stealthier
        if "ssrf" in title or "race condition" in title:
            return 0.8
        elif "information disclosure" in title:
            return 0.6
        elif "rce" in title or "command injection" in title:
            return 0.3  # RCE typically leaves loud logs
        else:
            return 0.5

    def _assess_detection_before(self, finding: dict) -> float:
        """Assess probability of detection before exploitation."""
        return 0.2  # Passive scanning unlikely to be detected

    def _assess_detection_during(self, finding: dict) -> float:
        """Assess probability of detection during exploitation."""
        title = finding.get("title", "").lower()

        if "rce" in title or "command injection" in title:
            return 0.8  # RCE typically leaves loud traces
        elif "ssrf" in title:
            return 0.4  # Medium detection risk
        elif "sql" in title:
            return 0.6  # SQL typically logged
        else:
            return 0.5

    def _assess_detection_after(self, finding: dict) -> float:
        """Assess probability of detection after exploitation."""
        return 0.7  # Forensics likely to find evidence

    def _assess_blast_radius(self, finding: dict) -> str:
        """Assess the blast radius of successful exploitation."""
        title = finding.get("title", "").lower()
        severity = finding.get("severity", "").lower()

        if severity == "critical":
            return "infrastructure"
        elif "rce" in title or "privilege escalation" in title:
            return "network"
        elif "sql" in title or "auth bypass" in title:
            return "service"
        else:
            return "localized"

    def _assess_reversibility(self, finding: dict) -> str:
        """Assess whether successful exploitation can be reversed."""
        title = finding.get("title", "").lower()

        if any(x in title for x in ["delete", "drop", "destroy"]):
            return "irreversible"
        elif any(x in title for x in ["modify", "inject"]):
            return "partially_reversible"
        else:
            return "reversible"

    def _generate_abort_conditions(self, finding: dict) -> list[str]:
        """Generate conditions under which exploitation should be aborted."""
        return [
            "If system monitoring detects unusual activity, abort immediately",
            "If firewall/IDS blocks request, abort to avoid alerts",
            "If target shows signs of active incident response, abort",
            "If system load spikes unexpectedly, abort to avoid DoS",
            "If any security tool initiates response, abort and document",
        ]

    def _calculate_risk_rating(self, severity: str, detection_during: float, blast_radius: str, reversibility: str) -> str:
        """Calculate overall risk rating for exploitation."""
        severity = severity.lower()

        if severity == "critical" and detection_during > 0.6 and blast_radius == "infrastructure":
            return "critical"
        elif severity in ["critical", "high"] and blast_radius in ["infrastructure", "network"]:
            return "high"
        elif reversibility == "irreversible" or blast_radius == "infrastructure":
            return "high"
        elif severity == "high":
            return "high"
        elif severity == "medium":
            return "medium"
        else:
            return "low"

    def _simulate_agent_execution(self, phase: Phase) -> list[dict]:
        """Simulate agent execution for a phase (in real system, this calls actual agents).

        For now, this returns example findings. In production, this would
        orchestrate actual agent execution.
        """
        # Dummy findings for simulation
        example_findings = {
            "reconnaissance": [
                {
                    "id": "find_001",
                    "type": "info_disclosure",
                    "title": "DNS records enumerated",
                    "severity": "low",
                    "description": "DNS records publicly available",
                    "affected_component": "DNS",
                    "cve_ids": [],
                }
            ],
            "network_scanning": [
                {
                    "id": "find_002",
                    "type": "open_port",
                    "title": "Open HTTP port detected",
                    "severity": "medium",
                    "description": "Port 80 open with nginx 1.18",
                    "affected_component": "HTTP server",
                    "cve_ids": [],
                }
            ],
            "vulnerability_scanning": [
                {
                    "id": "find_003",
                    "type": "cve_match",
                    "title": "nginx 1.18 - Potential vulnerability",
                    "severity": "medium",
                    "description": "Version may be vulnerable to known CVEs",
                    "affected_component": "nginx 1.18",
                    "cve_ids": ["CVE-2020-1234"],
                }
            ],
            "application_scanning": [
                {
                    "id": "find_004",
                    "type": "sql_injection",
                    "title": "SQL injection in login form",
                    "severity": "critical",
                    "description": "Login parameter vulnerable to SQL injection",
                    "affected_component": "/login",
                    "cve_ids": [],
                    "cvss_score": 9.8,
                }
            ],
        }

        findings = example_findings.get(phase.name, [])
        for finding in findings:
            phase.add_log(f"Found: {finding.get('title', 'unknown')}")

        return findings
