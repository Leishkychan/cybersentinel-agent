"""Base class for all CyberSentinel sub-agents.

Every sub-agent inherits from BaseAgent and must implement analyze().
The base class enforces safety rules — sub-agents cannot bypass them.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from cybersentinel.core.safety import validate_action
from cybersentinel.models.action import Action, ActionType
from cybersentinel.models.finding import Finding

if TYPE_CHECKING:
    from cybersentinel.models.session import Session


class BaseAgent(ABC):
    """Abstract base class for all sub-agents.

    Sub-agents:
    - Receive scoped input from the orchestrator
    - Analyze the input within their domain
    - Return findings to the orchestrator
    - NEVER take independent action (Rule 5)
    - NEVER make outbound requests (Rule 3)
    - NEVER handle credentials (Rule 2)
    """

    name: str = "base"
    description: str = "Base agent — not directly usable"

    def __init__(self, session: Session):
        self.session = session

    def validate(self, target: str, description: str) -> bool:
        """Validate that this agent's analysis action is permitted."""
        action = Action(
            type=ActionType.ANALYZE,
            agent_name=self.name,
            target=target,
            description=description,
            is_destructive=False,
            requires_credentials=False,
            requires_network=False,
        )
        return validate_action(self.name, action, target, self.session)

    @abstractmethod
    def analyze(self, target: str, context: dict) -> list[Finding]:
        """Perform analysis and return findings.

        Args:
            target: The target identifier (file path, hostname, etc.)
            context: Additional context (code content, config content,
                    scan results, etc.)

        Returns:
            List of Finding objects. These are returned to the
            orchestrator — the sub-agent does not act on them.
        """
        ...

    def log(self, message: str) -> None:
        """Log a message to the session audit trail."""
        self.session.log_event("agent_log", {
            "agent": self.name,
            "message": message,
        })
