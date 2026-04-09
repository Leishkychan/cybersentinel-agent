"""Orchestrator — the brain of CyberSentinel.

The orchestrator is responsible for:
1. Validating scope and permissions before anything runs
2. Classifying the task and dispatching to appropriate agents
3. Integrating autonomous reasoning for multi-phase scanning
4. Managing human checkpoints for exploitable findings
5. Aggregating findings from all agents
6. Resolving conflicts between overlapping findings
7. Enforcing the human checkpoint before any action
8. Storing scans to database and generating final reports

This is the central coordinator that wires up:
- ALL agent layers (Recon, Scanning, Intelligence, RedTeam, Exploit)
- The ReasoningEngine for autonomous scanning loops
- The SafetyLayer for human authorization gates
- The ReportingLayer for multi-format output
- The SentinelDatabase for persistent storage
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

from cybersentinel.core.reasoning import (
    ReasoningEngine,
    ReasoningResult,
    Phase,
    ExploitBriefing,
)
from cybersentinel.core.safety import (
    validate_action,
    validate_exploit,
    validate_text_output,
    HumanAuthRequest,
    require_human_auth,
)
from cybersentinel.models.finding import Finding, Severity
from cybersentinel.models.session import Session, SessionMode
from cybersentinel.storage.database import SentinelDatabase
from cybersentinel.reporting import (
    HTMLDashboardGenerator,
    PDFReportGenerator,
    MarkdownReportGenerator,
    ComplianceMapper,
    DeltaReporter,
)

logger = logging.getLogger(__name__)


# =============================================================================
# DISPATCH TABLE — Maps task types to agent pipelines
# =============================================================================

DISPATCH_TABLE: dict[str, list[str]] = {
    # Full comprehensive scan across all layers
    "full_scan": [
        # Recon agents
        "subdomain",
        "portscan",
        "osint",
        "dns_intel",
        "fingerprint",
        "waf_detect",
        # Scanning agents
        "sast",
        "dependency",
        "webapp",
        "nuclei",
        "traffic_analysis",
        "config_audit",
        "email_security",
        # Intelligence agents
        "cve_enrich",
        "threat_actor",
        "attack_chain",
        "multi_model",
        # RedTeam agents
        "playbook",
        "injection",
        "replay",
        "evasion",
        "pivot",
    ],
    # Source code focused
    "source_code": [
        "sast",
        "dependency",
        "cve_enrich",
        "threat_actor",
        "attack_chain",
        "playbook",
        "injection",
    ],
    # Web application assessment
    "web_app": [
        "fingerprint",
        "waf_detect",
        "webapp",
        "nuclei",
        "sast",
        "cve_enrich",
        "threat_actor",
        "playbook",
        "injection",
    ],
    # Infrastructure and network
    "infrastructure": [
        "portscan",
        "config_audit",
        "nuclei",
        "cve_enrich",
        "threat_actor",
        "playbook",
        "pivot",
    ],
    # Network reconnaissance
    "network": [
        "subdomain",
        "portscan",
        "osint",
        "dns_intel",
        "waf_detect",
        "nuclei",
        "cve_enrich",
        "threat_actor",
    ],
    # Reconnaissance only (passive)
    "recon_only": [
        "subdomain",
        "osint",
        "dns_intel",
        "fingerprint",
        "waf_detect",
    ],
    # Email and DNS security
    "email_security": [
        "dns_intel",
        "email_security",
    ],
    # Cloud-specific assessment
    "cloud": [
        "osint",
        "config_audit",
        "dependency",
        "webapp",
        "cve_enrich",
        "threat_actor",
    ],
}


# =============================================================================
# AGENT REGISTRY — Lazy imports for all agents
# =============================================================================

class AgentRegistry:
    """Central registry for all agents — lazy-loads on first use."""

    # Import cache
    _agent_cache: dict[str, type] = {}

    # Agent class paths — organized by layer
    AGENT_MODULES = {
        # Recon layer
        "subdomain": ("cybersentinel.agents.recon.subdomain", "SubdomainAgent"),
        "portscan": ("cybersentinel.agents.recon.portscan", "PortScanAgent"),
        "osint": ("cybersentinel.agents.recon.osint", "OSINTAgent"),
        "dns_intel": ("cybersentinel.agents.recon.dns_intel", "DNSIntelAgent"),
        "fingerprint": ("cybersentinel.agents.recon.fingerprint", "FingerprintAgent"),
        "waf_detect": ("cybersentinel.agents.recon.waf_detect", "WAFDetectAgent"),
        # Scanning layer
        "sast": ("cybersentinel.agents.scanning.sast", "SASTScanAgent"),
        "dependency": ("cybersentinel.agents.dependency", "DependencyScanAgent"),
        "webapp": ("cybersentinel.agents.scanning.webapp", "WebAppScanAgent"),
        "nuclei": ("cybersentinel.agents.scanning.nuclei", "NucleiScanAgent"),
        "traffic_analysis": ("cybersentinel.agents.scanning.traffic", "TrafficAnalysisAgent"),
        "config_audit": ("cybersentinel.agents.scanning.config", "ConfigAuditAgent"),
        "email_security": ("cybersentinel.agents.scanning.email", "EmailSecurityAgent"),
        # Intelligence layer
        "cve_enrich": ("cybersentinel.agents.intelligence.cve_enrich", "CVEEnrichAgent"),
        "threat_actor": ("cybersentinel.agents.intelligence.threat_actor", "ThreatActorAgent"),
        "attack_chain": ("cybersentinel.agents.intelligence.attack_chain", "AttackChainAgent"),
        "multi_model": ("cybersentinel.agents.intelligence.multi_model", "MultiModelAgent"),
        # RedTeam layer
        "playbook": ("cybersentinel.agents.redteam.playbook", "PlaybookAgent"),
        "injection": ("cybersentinel.agents.redteam.injection", "InjectionAgent"),
        "replay": ("cybersentinel.agents.redteam.replay", "ReplayAgent"),
        "evasion": ("cybersentinel.agents.redteam.evasion", "EvasionAgent"),
        "pivot": ("cybersentinel.agents.redteam.pivot", "PivotAgent"),
        # Exploit layer
        "exploit_briefing": ("cybersentinel.agents.exploit.briefing", "ExploitBriefingAgent"),
        "exploit_executor": ("cybersentinel.agents.exploit.executor", "ExploitExecutor"),
    }

    @classmethod
    def get_agent(cls, agent_name: str, session: Session) -> object:
        """Get an agent instance, lazy-loading the class if needed.

        Args:
            agent_name: Name of the agent to load
            session: Current session

        Returns:
            Instantiated agent object

        Raises:
            ValueError: If agent name is unknown
        """
        if agent_name not in cls.AGENT_MODULES:
            valid = ", ".join(cls.AGENT_MODULES.keys())
            raise ValueError(
                f"Unknown agent: '{agent_name}'. Valid agents: {valid}"
            )

        # Load class if not cached
        if agent_name not in cls._agent_cache:
            module_path, class_name = cls.AGENT_MODULES[agent_name]
            try:
                module = __import__(module_path, fromlist=[class_name])
                cls._agent_cache[agent_name] = getattr(module, class_name)
                logger.info(f"Loaded agent class: {agent_name}")
            except (ImportError, AttributeError) as e:
                raise ValueError(
                    f"Failed to load agent '{agent_name}': {e}"
                ) from e

        # Instantiate and return
        agent_class = cls._agent_cache[agent_name]
        return agent_class(session=session)


# =============================================================================
# ORCHESTRATOR — Central Coordinator
# =============================================================================

@dataclass
class Orchestrator:
    """Central coordinator for CyberSentinel agent operations.

    The orchestrator:
    1. Validates scope and permissions
    2. Classifies tasks and dispatches to agents
    3. Integrates the reasoning engine for autonomous scanning
    4. Manages human checkpoints and approvals
    5. Aggregates findings from all agents
    6. Resolves conflicts
    7. Generates reports in multiple formats
    8. Stores scans persistently

    Usage:
        session = Session(mode=SessionMode.GUIDED)
        session.add_target("target.com", approved_by="Operator")
        config = SentinelConfig()
        orch = Orchestrator(session=session, config=config)

        # Option 1: Autonomous reasoning
        result = orch.run_autonomous(goal="find vulnerabilities in target.com", max_depth=5)
        orch.checkpoint()
        orch.approve_checkpoint(approved_by="Operator")
        reports = orch.generate_reports(["html", "pdf", "markdown"], output_dir="./reports")

        # Option 2: Guided task execution
        orch.validate_scope()
        agents = orch.classify("web_app")
        for agent_name in agents:
            findings = orch.run_agent(agent_name, "target.com", context={})
        orch.checkpoint()
        orch.approve_checkpoint(approved_by="Operator")
        reports = orch.generate_reports(["markdown"], output_dir="./reports")
    """

    session: Session
    config: Optional[object] = None  # SentinelConfig — optional for testing
    db: Optional[SentinelDatabase] = None

    # State tracking
    dispatch_plan: list[str] = field(default_factory=list)
    findings_by_agent: dict[str, list[Finding]] = field(default_factory=dict)
    conflicts: list[dict] = field(default_factory=list)
    exploit_briefings: list[ExploitBriefing] = field(default_factory=list)
    reasoning_result: Optional[ReasoningResult] = None
    _checkpoint_data: Optional[dict] = None
    pending_auth_requests: dict[str, HumanAuthRequest] = field(default_factory=dict)

    def __post_init__(self):
        """Initialize orchestrator."""
        if self.db is None:
            self.db = SentinelDatabase(db_path=":memory:")
        logger.info(f"Orchestrator initialized for session {self.session.id}")

    # =========================================================================
    # SCOPE AND VALIDATION
    # =========================================================================

    def validate_scope(self) -> bool:
        """Verify the session has defined scope before any work begins.

        Returns:
            True if scope is valid

        Raises:
            ValueError: If scope is invalid
        """
        if not self.session.approved_targets:
            raise ValueError(
                "No targets in scope. Use session.add_target() to define "
                "the assessment scope before proceeding."
            )

        self.session.log_event("scope_validated", {
            "targets": self.session.approved_targets,
            "mode": self.session.mode.value,
        })

        logger.info(f"Scope validated: {len(self.session.approved_targets)} target(s)")
        return True

    # =========================================================================
    # TASK CLASSIFICATION AND DISPATCH
    # =========================================================================

    def classify(self, target_type: str) -> list[str]:
        """Determine which agents to invoke based on target type.

        Args:
            target_type: One of the keys in DISPATCH_TABLE

        Returns:
            Ordered list of agent names to invoke

        Raises:
            ValueError: If target_type is unknown
        """
        if target_type not in DISPATCH_TABLE:
            valid = ", ".join(DISPATCH_TABLE.keys())
            raise ValueError(
                f"Unknown target type: '{target_type}'. Valid types: {valid}"
            )

        self.dispatch_plan = DISPATCH_TABLE[target_type]
        self.session.log_event("task_classified", {
            "target_type": target_type,
            "dispatch_plan": self.dispatch_plan,
        })

        logger.info(f"Classified as '{target_type}': {len(self.dispatch_plan)} agents")
        return list(self.dispatch_plan)

    # =========================================================================
    # AGENT EXECUTION
    # =========================================================================

    def run_agent(
        self,
        agent_name: str,
        target: str,
        context: Optional[dict] = None,
    ) -> list[Finding]:
        """Execute a single agent and collect findings.

        Args:
            agent_name: Name of the agent to run
            target: Target identifier
            context: Additional context (code, config, etc.)

        Returns:
            List of findings from the agent

        Raises:
            ValueError: If agent is unknown
            Exception: If agent execution fails
        """
        context = context or {}

        # Get agent class
        try:
            agent = AgentRegistry.get_agent(agent_name, self.session)
        except ValueError as e:
            self.session.log_event("agent_execution_failed", {
                "agent": agent_name,
                "target": target,
                "reason": str(e),
            })
            logger.error(f"Failed to load agent '{agent_name}': {e}")
            raise

        # Log execution start
        self.session.log_event("agent_execution_started", {
            "agent": agent_name,
            "target": target,
        })

        logger.info(f"Running agent: {agent_name} on target: {target}")

        # Execute agent
        try:
            findings = agent.analyze(target, context)
        except Exception as e:
            self.session.log_event("agent_execution_failed", {
                "agent": agent_name,
                "target": target,
                "error": str(e),
            })
            logger.error(f"Agent '{agent_name}' failed: {e}")
            raise

        # Add findings to orchestrator
        for finding in findings:
            self.add_finding(finding)

        # Log completion
        self.session.log_event("agent_execution_completed", {
            "agent": agent_name,
            "target": target,
            "findings_count": len(findings),
        })

        logger.info(f"Agent '{agent_name}' produced {len(findings)} finding(s)")

        return findings

    # =========================================================================
    # FINDING MANAGEMENT
    # =========================================================================

    def add_finding(self, finding: Finding) -> None:
        """Register a finding from an agent.

        Findings are immutable — they can only be marked as false positives
        but never deleted (Safety Rule 5).

        Args:
            finding: Finding object to add
        """
        # Track by agent source
        if finding.agent_source not in self.findings_by_agent:
            self.findings_by_agent[finding.agent_source] = []
        self.findings_by_agent[finding.agent_source].append(finding)

        # Add to session (immutable)
        self.session.add_finding(finding.to_dict())

        logger.debug(f"Added finding: {finding.title} (severity: {finding.severity})")

    def get_all_findings(self) -> list[Finding]:
        """Return all findings across all agents, sorted by severity.

        Returns:
            List of Finding objects
        """
        all_findings = []
        for findings in self.findings_by_agent.values():
            all_findings.extend(findings)
        return sorted(all_findings, key=lambda f: list(Severity).index(f.severity))

    def resolve_conflicts(self) -> list[dict]:
        """Detect and flag conflicting findings from different agents.

        Conflicts are NOT auto-resolved. They're flagged for human review.
        The orchestrator presents both sides — the human decides.

        Returns:
            List of conflict records
        """
        all_findings = []
        for agent, findings in self.findings_by_agent.items():
            for f in findings:
                all_findings.append((agent, f))

        self.conflicts = []

        # Check for same component, different severity
        by_component: dict[str, list[tuple[str, Finding]]] = {}
        for agent, finding in all_findings:
            comp = finding.affected_component
            if comp not in by_component:
                by_component[comp] = []
            by_component[comp].append((agent, finding))

        for component, entries in by_component.items():
            if len(entries) > 1:
                severities = set(f.severity for _, f in entries)
                if len(severities) > 1:
                    self.conflicts.append({
                        "type": "severity_mismatch",
                        "component": component,
                        "findings": [
                            {
                                "agent": agent,
                                "severity": f.severity.value,
                                "title": f.title,
                            }
                            for agent, f in entries
                        ],
                        "resolution": "Using highest severity. Flagged for human review.",
                    })

        if self.conflicts:
            self.session.log_event("conflicts_detected", {
                "count": len(self.conflicts),
            })
            logger.warning(f"Detected {len(self.conflicts)} conflict(s)")

        return self.conflicts

    # =========================================================================
    # AUTONOMOUS REASONING INTEGRATION
    # =========================================================================

    def run_autonomous(
        self,
        goal: str,
        target: str = "",
        max_depth: int = 5,
    ) -> ReasoningResult:
        """Execute the autonomous reasoning loop for multi-phase scanning.

        The reasoning engine plans phases, the orchestrator executes them,
        findings flow back to the reasoning engine for replanning.

        Exploitation stops for human authorization.

        Args:
            goal: High-level goal (e.g., "find vulnerabilities in target.com")
            target: Optional target identifier
            max_depth: Maximum reasoning depth (default 5)

        Returns:
            ReasoningResult with all findings and exploit briefings
        """
        logger.info(f"Starting autonomous reasoning loop: {goal}")

        # Create reasoning engine
        reasoning_engine = ReasoningEngine(self.session, self.config)

        # Execute the reasoning loop
        self.reasoning_result = reasoning_engine.execute_loop(goal, max_depth)

        # Collect findings from all phases
        for phase in self.reasoning_result.phases_executed:
            for finding_dict in phase.findings:
                # Convert dict to Finding and add
                finding = self._dict_to_finding(finding_dict)
                if finding:
                    self.add_finding(finding)

        # Collect exploit briefings
        self.exploit_briefings = self.reasoning_result.exploit_briefings

        # Log completion
        self.session.log_event("autonomous_reasoning_complete", {
            "goal": goal,
            "phases": len(self.reasoning_result.phases_executed),
            "findings": self.reasoning_result.total_findings,
            "exploitable": len(self.reasoning_result.exploit_briefings),
            "depth": self.reasoning_result.depth_reached,
            "status": self.reasoning_result.status,
        })

        logger.info(
            f"Autonomous reasoning complete: "
            f"{self.reasoning_result.total_findings} findings, "
            f"{len(self.exploit_briefings)} exploitable, "
            f"depth {self.reasoning_result.depth_reached}"
        )

        return self.reasoning_result

    def _dict_to_finding(self, finding_dict: dict) -> Optional[Finding]:
        """Convert a finding dict to a Finding object.

        Args:
            finding_dict: Finding dictionary from reasoning engine

        Returns:
            Finding object or None if conversion fails
        """
        try:
            return Finding(
                title=finding_dict.get("title", "Unknown"),
                severity=Severity(finding_dict.get("severity", "low").lower()),
                description=finding_dict.get("description", ""),
                affected_component=finding_dict.get("affected_component", ""),
                agent_source=finding_dict.get("agent_source", "reasoning_engine"),
                cve_ids=finding_dict.get("cve_ids", []),
                cwe_ids=finding_dict.get("cwe_ids", []),
                cvss_score=finding_dict.get("cvss_score"),
                cvss_vector=finding_dict.get("cvss_vector"),
                epss_score=finding_dict.get("epss_score"),
                cisa_kev=finding_dict.get("cisa_kev", False),
                mitre_tactics=finding_dict.get("mitre_tactics", []),
                mitre_techniques=finding_dict.get("mitre_techniques", []),
                mitre_mitigations=finding_dict.get("mitre_mitigations", []),
                remediation=finding_dict.get("remediation", ""),
                compensating_controls=finding_dict.get("compensating_controls", ""),
                verification_steps=finding_dict.get("verification_steps", ""),
                detection_guidance=finding_dict.get("detection_guidance", ""),
                sigma_rule=finding_dict.get("sigma_rule"),
                confidence=finding_dict.get("confidence", "high"),
                status=finding_dict.get("status", "open"),
                false_positive_reason=finding_dict.get("false_positive_reason"),
                evidence=finding_dict.get("evidence", ""),
            )
        except Exception as e:
            logger.error(f"Failed to convert finding dict to Finding: {e}")
            return None

    # =========================================================================
    # EXPLOIT GATE — HARD LINE FOR HUMAN AUTHORIZATION
    # =========================================================================

    def create_exploit_auth_request(
        self,
        briefing: ExploitBriefing,
    ) -> HumanAuthRequest:
        """Create a human authorization request for an exploitable finding.

        This is the HARD LINE — CyberSentinel NEVER exploits without explicit
        human authorization.

        Args:
            briefing: The ExploitBriefing describing the exploit

        Returns:
            HumanAuthRequest that must be approved before exploitation
        """
        auth_request = require_human_auth(
            action_description=f"Execute exploit: {briefing.finding_title}",
            action_type="exploit",
            details=briefing.to_dict(),
        )

        self.pending_auth_requests[auth_request.request_id] = auth_request

        self.session.log_event("exploit_authorization_requested", {
            "request_id": auth_request.request_id,
            "finding_id": briefing.finding_id,
            "finding_title": briefing.finding_title,
            "risk_rating": briefing.risk_rating,
        })

        logger.warning(
            f"EXPLOITATION REQUIRED: {briefing.finding_title} "
            f"(risk: {briefing.risk_rating}) — awaiting human authorization"
        )

        return auth_request

    def authorize_exploit(
        self,
        request_id: str,
        approved_by: str,
    ) -> None:
        """Approve a pending exploit authorization request.

        Args:
            request_id: The request ID to approve
            approved_by: Name of the human approving

        Raises:
            KeyError: If request_id not found
        """
        if request_id not in self.pending_auth_requests:
            raise KeyError(f"Authorization request '{request_id}' not found")

        auth_request = self.pending_auth_requests[request_id]
        auth_request.approve(approved_by)

        self.session.log_event("exploit_authorized", {
            "request_id": request_id,
            "finding_id": auth_request.details.get("finding_id"),
            "approved_by": approved_by,
        })

        logger.info(f"Exploit authorized by {approved_by}: {request_id}")

    def deny_exploit(
        self,
        request_id: str,
        reason: str,
        denied_by: str,
    ) -> None:
        """Deny a pending exploit authorization request.

        Args:
            request_id: The request ID to deny
            reason: Reason for denial
            denied_by: Name of the human denying

        Raises:
            KeyError: If request_id not found
        """
        if request_id not in self.pending_auth_requests:
            raise KeyError(f"Authorization request '{request_id}' not found")

        auth_request = self.pending_auth_requests[request_id]
        auth_request.deny(reason)

        self.session.log_event("exploit_denied", {
            "request_id": request_id,
            "finding_id": auth_request.details.get("finding_id"),
            "reason": reason,
            "denied_by": denied_by,
        })

        logger.info(f"Exploit denied by {denied_by}: {request_id}")

    # =========================================================================
    # CHECKPOINT — MANDATORY HUMAN REVIEW POINT
    # =========================================================================

    def checkpoint(self) -> str:
        """Generate the mandatory human checkpoint.

        This is the STOP POINT (Safety Rule 1). No remediation commands,
        no report generation, no action of any kind until the human
        reviews and approves.

        Returns:
            Formatted checkpoint string for display
        """
        self.session.checkpoint_reached = True

        # Resolve conflicts
        self.resolve_conflicts()

        # Count by severity
        severity_counts = {s.value: 0 for s in Severity}
        all_findings = self.get_all_findings()
        for f in all_findings:
            severity_counts[f.severity.value] += 1

        self._checkpoint_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "targets": self.session.approved_targets,
            "mode": self.session.mode.value,
            "agents_invoked": list(self.findings_by_agent.keys()),
            "total_findings": len(all_findings),
            "severity_counts": severity_counts,
            "conflicts": len(self.conflicts),
            "exploit_briefings": len(self.exploit_briefings),
            "pending_authorizations": len(
                [ar for ar in self.pending_auth_requests.values() if not ar.approved]
            ),
        }

        self.session.log_event("checkpoint_presented", self._checkpoint_data)

        # Build the checkpoint display
        lines = [
            "",
            "═" * 70,
            "  CHECKPOINT: Findings Ready for Review",
            "═" * 70,
            "",
            f"  Scope: {', '.join(self.session.approved_targets)}",
            f"  Mode: {self.session.mode.value}",
            f"  Agents Invoked: {', '.join(self.findings_by_agent.keys())}",
            f"  Total Findings: {len(all_findings)}",
            f"    Critical: {severity_counts['critical']}  |  "
            f"High: {severity_counts['high']}  |  "
            f"Medium: {severity_counts['medium']}  |  "
            f"Low: {severity_counts['low']}  |  "
            f"Info: {severity_counts['informational']}",
            "",
        ]

        if self.exploit_briefings:
            lines.extend([
                f"  EXPLOITABLE VULNERABILITIES: {len(self.exploit_briefings)}",
                f"    Requires human authorization before exploitation",
                "",
            ])

        if self.conflicts:
            lines.append(f"  Conflicts/Ambiguities: {len(self.conflicts)}")
            for c in self.conflicts:
                lines.append(f"    - {c['component']}: {c['type']}")
            lines.append("")

        pending_auths = [
            ar for ar in self.pending_auth_requests.values() if not ar.approved
        ]
        if pending_auths:
            lines.extend([
                f"  PENDING AUTHORIZATIONS: {len(pending_auths)}",
                f"    Must be approved/denied before proceeding",
                "",
            ])

        lines.extend([
            "  AWAITING HUMAN APPROVAL before:",
            "    □ Generating remediation commands",
            "    □ Executing any exploits",
            "    □ Producing final report",
            "    □ Any recommended actions",
            "",
            "═" * 70,
            "",
        ])

        return "\n".join(lines)

    def approve_checkpoint(self, approved_by: str) -> None:
        """Human approves the checkpoint to proceed.

        Args:
            approved_by: Name of the human approving
        """
        self.session.checkpoint_approved = True
        self.session.log_event("checkpoint_approved", {
            "approved_by": approved_by,
        })

        logger.info(f"Checkpoint approved by {approved_by}")

    def reject_findings(
        self,
        finding_indices: list[int],
        reason: str,
        rejected_by: str,
    ) -> None:
        """Human rejects specific findings as false positives.

        Findings are NOT deleted (Rule 5) — only marked as false positive.

        Args:
            finding_indices: Indices of findings to reject
            reason: Reason for rejection
            rejected_by: Name of the human rejecting
        """
        for idx in finding_indices:
            self.session.mark_false_positive(idx, reason, rejected_by)

        logger.info(f"{rejected_by} marked {len(finding_indices)} finding(s) as false positive")

    # =========================================================================
    # REPORTING INTEGRATION
    # =========================================================================

    def generate_reports(
        self,
        formats: list[str],
        output_dir: str = "./reports",
        include_compliance: bool = False,
        baseline_scan_id: Optional[str] = None,
    ) -> dict[str, str]:
        """Generate reports in multiple formats.

        Args:
            formats: List of formats ("html", "pdf", "markdown")
            output_dir: Directory to write reports to
            include_compliance: Include compliance mapping (NIST, CIS, etc.)
            baseline_scan_id: For delta reporting (compare against baseline)

        Returns:
            Dictionary mapping format to report path

        Raises:
            PermissionError: If checkpoint not approved
        """
        if not self.session.checkpoint_approved:
            raise PermissionError(
                "Cannot generate report before checkpoint approval. "
                "Call approve_checkpoint() after human review."
            )

        findings = self.get_all_findings()
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        reports = {}

        # Markdown report
        if "markdown" in formats:
            md_gen = MarkdownReportGenerator()
            md_content = md_gen.generate(
                session=self.session,
                findings=findings,
                conflicts=self.conflicts,
                reasoning_result=self.reasoning_result,
            )
            md_path = output_path / f"report_{self.session.id}.md"
            with open(md_path, "w") as f:
                f.write(md_content)
            reports["markdown"] = str(md_path)
            logger.info(f"Generated markdown report: {md_path}")

        # HTML dashboard
        if "html" in formats:
            html_gen = HTMLDashboardGenerator()
            html_content = html_gen.generate(
                session=self.session,
                findings=findings,
                conflicts=self.conflicts,
                reasoning_result=self.reasoning_result,
            )
            html_path = output_path / f"dashboard_{self.session.id}.html"
            with open(html_path, "w") as f:
                f.write(html_content)
            reports["html"] = str(html_path)
            logger.info(f"Generated HTML dashboard: {html_path}")

        # PDF report
        if "pdf" in formats:
            if PDFReportGenerator is None:
                logger.warning("PDF report generation requested but PDFReportGenerator not available (reportlab dependency missing)")
            else:
                pdf_gen = PDFReportGenerator()
                pdf_path = output_path / f"report_{self.session.id}.pdf"
                pdf_gen.generate(
                    session=self.session,
                    findings=findings,
                    conflicts=self.conflicts,
                    output_path=str(pdf_path),
                )
                reports["pdf"] = str(pdf_path)
                logger.info(f"Generated PDF report: {pdf_path}")

        # Compliance mapping
        if include_compliance:
            compliance_gen = ComplianceMapper()
            compliance_report = compliance_gen.map_findings(findings)
            compliance_path = output_path / f"compliance_{self.session.id}.json"
            with open(compliance_path, "w") as f:
                json.dump(compliance_report, f, indent=2)
            reports["compliance"] = str(compliance_path)
            logger.info(f"Generated compliance report: {compliance_path}")

        # Delta report (compare against baseline)
        if baseline_scan_id:
            delta_reporter = DeltaReporter(self.db)
            delta_report = delta_reporter.compare_scans(
                baseline_scan_id=baseline_scan_id,
                current_scan_id=self.session.id,
            )
            delta_path = output_path / f"delta_{self.session.id}.json"
            with open(delta_path, "w") as f:
                json.dump(delta_report.to_dict(), f, indent=2)
            reports["delta"] = str(delta_path)
            logger.info(f"Generated delta report: {delta_path}")

        return reports

    def generate_report(self, format: str = "markdown") -> str:
        """Generate a single report in the specified format.

        Args:
            format: Report format ("markdown", "html", "pdf")

        Returns:
            Report content as string (or path for PDF)

        Raises:
            PermissionError: If checkpoint not approved
            ValueError: If format is unknown
        """
        if not self.session.checkpoint_approved:
            raise PermissionError(
                "Cannot generate report before checkpoint approval. "
                "Call approve_checkpoint() after human review."
            )

        findings = self.get_all_findings()
        scan_metadata = {
            "session_id": self.session.id,
            "mode": self.session.mode.value,
            "targets": self.session.approved_targets,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        chains = []  # Attack chains from reasoning
        compliance_map = {}  # Compliance mappings

        if format == "markdown":
            gen = MarkdownReportGenerator()
            return gen.generate(
                findings=findings,
                scan_metadata=scan_metadata,
                chains=chains,
                compliance_map=compliance_map,
            )

        elif format == "html":
            gen = HTMLDashboardGenerator()
            return gen.generate(
                findings=findings,
                scan_metadata=scan_metadata,
                chains=chains,
                compliance_map=compliance_map,
            )

        elif format == "pdf":
            if PDFReportGenerator is None:
                raise RuntimeError("PDF report generation requested but PDFReportGenerator not available (reportlab dependency missing)")
            gen = PDFReportGenerator()
            output_path = f"/tmp/report_{self.session.id}.pdf"
            gen.generate(
                session=self.session,
                findings=findings,
                conflicts=self.conflicts,
                output_path=output_path,
            )
            return output_path

        else:
            raise ValueError(f"Unknown report format: '{format}'")

    # =========================================================================
    # STORAGE INTEGRATION — Persistent Scan History
    # =========================================================================

    def save_scan(self) -> str:
        """Save this scan to the database.

        Returns:
            Scan ID for future reference
        """
        if not self.db:
            raise RuntimeError("Database not initialized")

        findings = self.get_all_findings()
        metadata = {
            "mode": self.session.mode.value,
            "targets": self.session.approved_targets,
            "dispatch_plan": self.dispatch_plan,
            "conflicts": len(self.conflicts),
            "reasoning_depth": (
                self.reasoning_result.depth_reached
                if self.reasoning_result
                else 0
            ),
        }

        # Save scan record
        self.db.add_scan(
            scan_id=self.session.id,
            target=", ".join(self.session.approved_targets),
            timestamp=datetime.now(timezone.utc).isoformat(),
            mode=self.session.mode.value,
            findings_count=len(findings),
            metadata=json.dumps(metadata),
        )

        # Save findings
        for finding in findings:
            self.db.add_finding(
                scan_id=self.session.id,
                finding_id=f"{self.session.id}_{finding.title.replace(' ', '_')}",
                title=finding.title,
                severity=finding.severity.value,
                component=finding.affected_component,
                cve_ids=finding.cve_ids,
                cwe_ids=finding.cwe_ids,
                cvss_score=finding.cvss_score,
                epss_score=finding.epss_score,
                cisa_kev=finding.cisa_kev,
                mitre_techniques=finding.mitre_techniques,
                agent_source=finding.agent_source,
                status=finding.status,
                confidence=finding.confidence,
                full_data=json.dumps(finding.to_dict()),
            )

        self.session.log_event("scan_saved", {
            "scan_id": self.session.id,
            "findings": len(findings),
        })

        logger.info(f"Scan saved to database: {self.session.id}")
        return self.session.id

    def set_baseline(self) -> None:
        """Mark the current scan as the baseline for future comparisons.

        Used for delta reporting.
        """
        if not self.db:
            raise RuntimeError("Database not initialized")

        target = ", ".join(self.session.approved_targets)
        self.db.set_baseline(
            target=target,
            scan_id=self.session.id,
        )

        self.session.log_event("baseline_set", {
            "scan_id": self.session.id,
            "target": target,
        })

        logger.info(f"Baseline set for target: {target}")

    def save_audit_log(self, output_path: Optional[str] = None) -> str:
        """Export the immutable audit log to a file.

        Args:
            output_path: Path to write audit log (optional)

        Returns:
            Path to the audit log file
        """
        if output_path is None:
            output_path = f"audit_log_{self.session.id}.json"

        audit_log = self.session.export_audit_log()

        with open(output_path, "w") as f:
            json.dump(audit_log, f, indent=2)

        logger.info(f"Audit log saved: {output_path}")
        return output_path

    # =========================================================================
    # UTILITY METHODS
    # =========================================================================

    def get_session_summary(self) -> dict:
        """Get a summary of the current session state.

        Returns:
            Dictionary with session summary
        """
        findings = self.get_all_findings()
        severity_counts = {s.value: 0 for s in Severity}
        for f in findings:
            severity_counts[f.severity.value] += 1

        return {
            "session_id": self.session.id,
            "mode": self.session.mode.value,
            "targets": self.session.approved_targets,
            "agents_invoked": list(self.findings_by_agent.keys()),
            "total_findings": len(findings),
            "severity_counts": severity_counts,
            "conflicts": len(self.conflicts),
            "exploit_briefings": len(self.exploit_briefings),
            "checkpoint_reached": self.session.checkpoint_reached,
            "checkpoint_approved": self.session.checkpoint_approved,
            "reasoning_depth": (
                self.reasoning_result.depth_reached
                if self.reasoning_result
                else 0
            ),
        }
