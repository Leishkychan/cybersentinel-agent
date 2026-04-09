"""Sub-agent definitions for CyberSentinel.

Each sub-agent has a defined scope, inputs, outputs, and boundaries.
Sub-agents NEVER take independent action — they return findings to
the orchestrator (Safety Rule 5).

Available agent categories:
- recon: Reconnaissance agents (subdomain discovery, port scanning, OSINT, etc.)
- scanning: Vulnerability scanning agents (SAST, dependency scanning, web app scanning)
- intelligence: Intelligence enrichment agents (CVE enrichment, threat actor profiling)
- redteam: Red team operation agents (exploitation playbooks, injection, evasion)
- exploit: Exploitation layer agents (briefing, execution)
"""

from cybersentinel.agents.base import BaseAgent

# Lazy imports for sub-packages to avoid circular dependencies
# Import from sub-packages as needed: from cybersentinel.agents.recon import SubdomainAgent

__all__ = [
    "BaseAgent",
]
