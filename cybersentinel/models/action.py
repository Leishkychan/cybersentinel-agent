"""Action model — represents any action an agent wants to perform."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class ActionType(str, Enum):
    ANALYZE = "analyze"
    REPORT = "report"
    RECOMMEND = "recommend"
    GENERATE_COMMANDS = "generate_commands"
    EXECUTE_WITH_APPROVAL = "execute_with_approval"


@dataclass
class Action:
    """Represents an action that an agent wants to take.

    Every action goes through validate_action() in the safety layer
    before it's permitted. Destructive actions are permanently blocked
    regardless of mode or approval status.
    """
    type: ActionType
    agent_name: str
    target: str
    description: str
    command: Optional[str] = None  # The actual command, if applicable
    is_destructive: bool = False
    requires_credentials: bool = False
    requires_network: bool = False
    approved_by_human: bool = False

    def __str__(self) -> str:
        status = "APPROVED" if self.approved_by_human else "PENDING"
        return (
            f"[{status}] {self.type.value}: {self.description}\n"
            f"  Agent: {self.agent_name}\n"
            f"  Target: {self.target}"
        )
