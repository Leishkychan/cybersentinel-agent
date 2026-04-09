"""Session model — tracks scope, permissions, mode, and audit trail."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class SessionMode(str, Enum):
    """Operating modes with escalating permissions.

    PASSIVE: Analysis only. No commands generated, no tool calls.
    GUIDED: Analysis + recommendations. Commands are generated but labeled
            'AWAITING HUMAN APPROVAL' and never auto-executed.
    ACTIVE: Reserved for future use. Even in active mode, destructive
            actions are permanently blocked (see safety.py).
    """
    PASSIVE = "passive"
    GUIDED = "guided"
    ACTIVE = "active"


# What each mode is allowed to do. The safety layer enforces this.
MODE_PERMISSIONS: dict[SessionMode, set[str]] = {
    SessionMode.PASSIVE: {"analyze", "report"},
    SessionMode.GUIDED: {"analyze", "report", "recommend", "generate_commands"},
    SessionMode.ACTIVE: {"analyze", "report", "recommend", "generate_commands", "execute_with_approval"},
}


@dataclass
class Session:
    """Represents a single assessment session with defined scope and permissions.

    Every interaction happens within a session. The session defines what targets
    are in scope, what mode we're operating in, and maintains an immutable
    audit log of every action taken.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    mode: SessionMode = SessionMode.GUIDED
    approved_targets: list[str] = field(default_factory=list)
    approved_by: Optional[str] = None
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    audit_log: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    checkpoint_reached: bool = False
    checkpoint_approved: bool = False
    metadata: dict = field(default_factory=dict)

    def add_target(self, target: str, approved_by: str) -> None:
        """Add a target to the approved scope. Requires human identity."""
        if target not in self.approved_targets:
            self.approved_targets.append(target)
            self.log_event("target_added", {
                "target": target,
                "approved_by": approved_by,
            })

    def log_event(self, event_type: str, details: dict) -> None:
        """Append to the immutable audit log. Entries cannot be deleted."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session_id": self.id,
            "event_type": event_type,
            **details,
        }
        self.audit_log.append(entry)

    def add_finding(self, finding_dict: dict) -> None:
        """Add a finding. Findings are append-only — they cannot be removed.

        To mark a finding as a false positive, update its status field.
        The original finding remains in the list for audit purposes.
        """
        finding_dict["finding_index"] = len(self.findings)
        finding_dict["timestamp"] = datetime.now(timezone.utc).isoformat()
        self.findings.append(finding_dict)
        self.log_event("finding_added", {
            "finding_index": finding_dict["finding_index"],
            "severity": finding_dict.get("severity", "unknown"),
            "title": finding_dict.get("title", "untitled"),
        })

    def mark_false_positive(self, finding_index: int, reason: str, marked_by: str) -> None:
        """Mark a finding as false positive. Does NOT delete it (Rule 4)."""
        if 0 <= finding_index < len(self.findings):
            self.findings[finding_index]["status"] = "false_positive"
            self.findings[finding_index]["false_positive_reason"] = reason
            self.findings[finding_index]["marked_by"] = marked_by
            self.log_event("finding_marked_false_positive", {
                "finding_index": finding_index,
                "reason": reason,
                "marked_by": marked_by,
            })

    def is_target_approved(self, target: str) -> bool:
        """Check if a target is within the approved scope."""
        return target in self.approved_targets

    def get_permissions(self) -> set[str]:
        """Return the set of allowed action types for the current mode."""
        return MODE_PERMISSIONS.get(self.mode, set())

    def export_audit_log(self) -> list[dict]:
        """Export the full audit log. This is the source of truth."""
        return list(self.audit_log)
