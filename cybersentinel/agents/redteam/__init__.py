"""Red Team layer agents (Layer 4).

Controlled red team operations including exploitation playbooks, injection testing,
attack replay, evasion analysis, and pivot analysis. All actions require explicit
human authorization.
"""

from cybersentinel.agents.redteam.playbook import PlaybookAgent
from cybersentinel.agents.redteam.injection import InjectionAgent
from cybersentinel.agents.redteam.replay import ReplayAgent
from cybersentinel.agents.redteam.evasion import EvasionAgent
from cybersentinel.agents.redteam.pivot import PivotAgent

__all__ = [
    "PlaybookAgent",
    "InjectionAgent",
    "ReplayAgent",
    "EvasionAgent",
    "PivotAgent",
]
