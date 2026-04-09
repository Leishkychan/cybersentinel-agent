"""Safety enforcement layer — the 6 non-negotiable rules as executable code.

CyberSentinel's safety model is built on explicit authorization gates:

Rule 1: SCANNING IS UNRESTRICTED — Passive and active scanning requires no
        human authorization. CyberSentinel can scan autonomously. This is the
        core of its reasoning engine.

Rule 2: EXPLOITATION REQUIRES HUMAN AUTHORIZATION — When an exploitable
        vulnerability is found, a full briefing is generated and the system
        STOPS. Exploitation never happens without explicit human approval.

Rule 3: FULL BRIEFING REQUIRED — Before any exploit is authorized, a complete
        briefing with risk assessment, detection probabilities, blast radius,
        abort conditions, and remediation impact must be reviewed.

Rule 4: NO CREDENTIAL PERSISTENCE — Credentials are never stored, persisted,
        or transmitted. Credential handling is redacted from output.

Rule 5: ALL FINDINGS IMMUTABLE — Findings cannot be deleted. Mark as false
        positive to update status, but the original finding remains in the
        immutable audit log.

Rule 6: EVERY ACTION LOGGED — Complete audit trail of all actions, approvals,
        and denials. The audit log is the source of truth.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from cybersentinel.models.action import Action
    from cybersentinel.models.session import Session


# --- Custom Exceptions ---

class SafetyViolation(Exception):
    """Base class for all safety violations."""
    rule: int = 0

    def __init__(self, message: str):
        self.message = message
        super().__init__(f"[SAFETY RULE {self.rule}] {message}")


class ScopeViolation(SafetyViolation):
    """Target is not in the approved scope."""
    rule = 0


class ModeViolation(SafetyViolation):
    """Action type is not permitted in the current session mode."""
    rule = 1


class HardStop(SafetyViolation):
    """Destructive action attempted — permanently blocked."""
    rule = 1


class CredentialViolation(SafetyViolation):
    """Credentials detected in input or output."""
    rule = 4


class NetworkViolation(SafetyViolation):
    """Agent attempted unauthorized outbound network request."""
    rule = 1


class ImmutabilityViolation(SafetyViolation):
    """Attempt to delete or suppress findings."""
    rule = 5


class IndependentActionViolation(SafetyViolation):
    """Sub-agent attempted to act independently."""
    rule = 6


class ExploitationWithoutAuthorizationViolation(SafetyViolation):
    """Attempt to exploit without human authorization."""
    rule = 2


# --- Credential Detection ---

CREDENTIAL_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key"),
    re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*\S+"),
    re.compile(r"(?i)api[_\-]?key\s*[:=]\s*\S+"),
    re.compile(r"(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*"),
    re.compile(r"(?i)token\s*[:=]\s*[a-zA-Z0-9\-._~+/]{20,}"),
    re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE\sKEY-----"),
    re.compile(r"(?i)secret\s*[:=]\s*\S{8,}"),
]


def contains_credentials(text: str) -> bool:
    """Check if text contains anything that looks like credentials."""
    for pattern in CREDENTIAL_PATTERNS:
        if pattern.search(text):
            return True
    return False


def scan_for_credentials(text: str) -> list[str]:
    """Return list of credential pattern matches found in text."""
    matches = []
    for pattern in CREDENTIAL_PATTERNS:
        found = pattern.findall(text)
        if found:
            matches.extend(found)
    return matches


# --- Human Authorization Types ---

@dataclass
class HumanAuthRequest:
    """Request for human authorization of an action.

    This is issued when the system encounters an action that requires
    human decision-making (e.g., exploitation).
    """
    request_id: str
    action_type: str  # "exploit", "manual_command", "data_extraction"
    description: str
    details: dict = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    approved: bool = False
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    denial_reason: Optional[str] = None

    def approve(self, approved_by: str) -> None:
        """Mark this request as approved."""
        self.approved = True
        self.approved_by = approved_by
        self.approved_at = datetime.now(timezone.utc).isoformat()

    def deny(self, reason: str) -> None:
        """Mark this request as denied."""
        self.approved = False
        self.denial_reason = reason

    def to_dict(self) -> dict:
        """Serialize for logging."""
        return {
            "request_id": self.request_id,
            "action_type": self.action_type,
            "description": self.description,
            "details": self.details,
            "created_at": self.created_at,
            "approved": self.approved,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at,
            "denial_reason": self.denial_reason,
        }


# --- Core Safety Functions ---

def validate_action(
    agent_name: str,
    action: "Action",
    target: str,
    session: "Session",
) -> bool:
    """Validate an action against all safety rules.

    CHANGED from original: Scanning actions are now UNRESTRICTED.
    Only exploitation requires authorization.

    Returns:
        True if the action is permitted

    Raises:
        ScopeViolation: Target not in approved scope
        ModeViolation: Action type not permitted in current mode
        HardStop: Destructive action attempted (always blocked)
        CredentialViolation: Credentials detected
    """
    # Rule 0: Scope validation
    if target and not session.is_target_approved(target):
        session.log_event("scope_violation", {
            "agent": agent_name,
            "target": target,
            "action": action.type.value,
        })
        raise ScopeViolation(
            f"Target '{target}' is not in the approved scope. "
            f"Approved targets: {session.approved_targets}"
        )

    # Rule 1b: Destructive actions are NEVER permitted
    if action.is_destructive:
        session.log_event("hard_stop", {
            "agent": agent_name,
            "action": action.type.value,
            "description": action.description,
            "reason": "Destructive actions are permanently blocked",
        })
        raise HardStop(
            f"Destructive action blocked: '{action.description}'. "
            f"CyberSentinel never performs destructive actions."
        )

    # Rule 4: No credentials in commands
    if action.requires_credentials:
        session.log_event("credential_violation", {
            "agent": agent_name,
            "action": action.type.value,
        })
        raise CredentialViolation(
            f"Action requires credentials. Provide command template with <YOUR_CREDENTIAL> placeholders."
        )

    if action.command and contains_credentials(action.command):
        session.log_event("credential_in_command", {
            "agent": agent_name,
            "action": action.type.value,
        })
        raise CredentialViolation(
            f"Credentials detected in command text. Use placeholder values like <YOUR_API_KEY>."
        )

    # Rule 1: Scan actions are unrestricted (CHANGED from original)
    # Only exploitation requires mode-based permission checks
    if "exploit" in action.type.value:
        if action.type.value not in session.get_permissions():
            session.log_event("mode_violation", {
                "agent": agent_name,
                "action_type": action.type.value,
                "session_mode": session.mode.value,
                "allowed": list(session.get_permissions()),
            })
            raise ModeViolation(
                f"Action '{action.type.value}' is not permitted in "
                f"'{session.mode.value}' mode."
            )

    # All checks passed
    session.log_event("action_validated", {
        "agent": agent_name,
        "action_type": action.type.value,
        "target": target,
    })
    return True


def validate_exploit(
    finding: dict,
    briefing: "ExploitBriefing",
    session: "Session",
) -> bool:
    """Validate that a human has explicitly authorized this specific exploit.

    Rule 2: Exploitation requires human authorization.

    Args:
        finding: The vulnerability finding to exploit
        briefing: The exploit briefing for review
        session: Current session (should contain auth requests)

    Returns:
        True if exploit is authorized

    Raises:
        ExploitationWithoutAuthorizationViolation: If not authorized
    """
    finding_id = finding.get("id", "unknown")

    # Check if this exploit has been authorized
    auth_requests = [
        event for event in session.audit_log
        if event.get("event_type") == "exploit_authorized" and
        event.get("finding_id") == finding_id
    ]

    if not auth_requests:
        session.log_event("exploit_without_authorization_attempted", {
            "finding_id": finding_id,
            "finding_title": finding.get("title", "unknown"),
            "reason": "No human authorization found for this exploit",
        })
        raise ExploitationWithoutAuthorizationViolation(
            f"Finding {finding_id} has not been authorized for exploitation. "
            f"Human must explicitly approve this action."
        )

    # At least one authorization must exist
    latest_auth = auth_requests[-1]

    if not latest_auth.get("approved", False):
        raise ExploitationWithoutAuthorizationViolation(
            f"Finding {finding_id} authorization was not approved."
        )

    session.log_event("exploit_authorization_validated", {
        "finding_id": finding_id,
        "authorized_by": latest_auth.get("approved_by"),
        "authorized_at": latest_auth.get("authorized_at"),
    })

    return True


def require_human_auth(
    action_description: str,
    action_type: str = "exploit",
    details: Optional[dict] = None,
) -> HumanAuthRequest:
    """Generate a human authorization request.

    This creates an authorization request that must be approved before
    the action can proceed.

    Args:
        action_description: Human-readable description
        action_type: Type of action (exploit, manual_command, etc.)
        details: Additional details for review

    Returns:
        HumanAuthRequest object that must be approved
    """
    import uuid

    request_id = str(uuid.uuid4())

    request = HumanAuthRequest(
        request_id=request_id,
        action_type=action_type,
        description=action_description,
        details=details or {},
    )

    return request


def validate_text_output(text: str, session: "Session") -> str:
    """Scan agent output for credential leaks before returning to user.

    Rule 4: Credentials are never persisted or transmitted.

    Args:
        text: Output text to check
        session: Current session

    Returns:
        Cleaned text with credentials redacted
    """
    matches = scan_for_credentials(text)

    if matches:
        session.log_event("credential_redacted_from_output", {
            "match_count": len(matches),
        })
        for match in matches:
            text = text.replace(match, "[REDACTED — CREDENTIAL DETECTED]")
        text = (
            "⚠️ WARNING: Credentials were detected in this output and have been redacted. "
            "Never paste credentials into AI agent prompts.\n\n" + text
        )

    return text


def audit_log_entry(
    session: "Session",
    event_type: str,
    agent_name: Optional[str] = None,
    target: Optional[str] = None,
    details: Optional[dict] = None,
) -> None:
    """Add an entry to the immutable audit log.

    Rule 6: Every action is logged.

    Args:
        session: Current session
        event_type: Type of event (action_executed, finding_added, etc.)
        agent_name: Name of agent performing action
        target: Target of action
        details: Additional details
    """
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "session_id": session.id,
        "event_type": event_type,
    }

    if agent_name:
        entry["agent"] = agent_name
    if target:
        entry["target"] = target
    if details:
        entry.update(details)

    session.log_event(event_type, entry)


# --- Exploit Briefing Type (imported from reasoning module) ---

# Note: In production, this would be imported:
# from cybersentinel.core.reasoning import ExploitBriefing
# For now, we define a minimal interface here to avoid circular imports

class ExploitBriefing:
    """Placeholder for exploit briefing (imported from reasoning module in practice)."""
    def __init__(
        self,
        finding_id: str,
        finding_title: str,
        exploit_steps: list[str],
        detection_probability_during: float,
        blast_radius: str,
        abort_conditions: list[str],
    ):
        self.finding_id = finding_id
        self.finding_title = finding_title
        self.exploit_steps = exploit_steps
        self.detection_probability_during = detection_probability_during
        self.blast_radius = blast_radius
        self.abort_conditions = abort_conditions
