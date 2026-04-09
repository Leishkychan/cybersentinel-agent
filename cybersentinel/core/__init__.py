"""Core framework — safety layer, orchestrator, reasoning engine, and configuration.

Implements the core safety-first architecture including:
- Safety validation for all actions (scope, authorization, credentials, network)
- Orchestrator for multi-agent coordination
- Reasoning engine for phase-based attack analysis
- Configuration management for scan parameters and reporting settings
"""

from cybersentinel.core.safety import (
    validate_action,
    validate_exploit,
    require_human_auth,
    validate_text_output,
    ScopeViolation,
    ModeViolation,
    HardStop,
    CredentialViolation,
    NetworkViolation,
    ExploitationWithoutAuthorizationViolation,
    HumanAuthRequest,
)
from cybersentinel.core.orchestrator import Orchestrator
from cybersentinel.core.reasoning import (
    ReasoningEngine,
    Phase,
    ExploitBriefing,
    ReasoningResult,
)
from cybersentinel.core.config import SentinelConfig

__all__ = [
    "validate_action",
    "validate_exploit",
    "require_human_auth",
    "validate_text_output",
    "ScopeViolation",
    "ModeViolation",
    "HardStop",
    "CredentialViolation",
    "NetworkViolation",
    "ExploitationWithoutAuthorizationViolation",
    "HumanAuthRequest",
    "Orchestrator",
    "ReasoningEngine",
    "Phase",
    "ExploitBriefing",
    "ReasoningResult",
    "SentinelConfig",
]
