# CyberSentinel Agent

Defensive cybersecurity agent framework with safety-first architecture. Built on the principle that blue team needs actionable output — not just "you have a vulnerability," but severity, CVE reference, affected component, MITRE ATT&CK mapping, and remediation steps.

## Architecture

```
ORCHESTRATOR
├── validates scope + permissions before anything runs
├── dispatches to sub-agents based on target type
├── aggregates findings and resolves conflicts
├── enforces human checkpoint before any action
└── generates report — never acts on findings

SUB-AGENTS (read-only, scoped):
├── SAST Agent        → static code analysis
├── Dependency Agent  → CVE matching on packages
├── Config Agent      → misconfigs (IAM, firewall rules, secrets in env)
├── Threat Model Agent → MITRE ATT&CK mapping of findings
└── Report Agent      → formats output, assigns severity
```

## Safety Protocol — 5 Non-Negotiable Rules

These are enforced in code, not just policy. Every action passes through `validate_action()` before execution.

| Rule | What It Does | Enforcement |
|------|-------------|-------------|
| 1 | No command execution without human approval | `ModeViolation` / `HardStop` exception |
| 2 | No credentials touched, stored, or transmitted | `CredentialViolation` exception + output redaction |
| 3 | No outbound requests to targets | `NetworkViolation` exception |
| 4 | Immutable findings — agents can't delete output | No delete methods exist on Session/Orchestrator |
| 5 | Sub-agents report to orchestrator only | BaseAgent enforces via validate() |

## Quick Start

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/cybersentinel-agent.git
cd cybersentinel-agent

# Install
pip install -e ".[dev]"

# Run tests (30 tests covering all safety rules)
pytest tests/ -v

# Run the demo
python demo/demo_session.py
```

## Demo Targets

Spin up intentionally vulnerable apps for safe, legal testing:

```bash
cd demo
docker compose up -d
# DVWA:       http://localhost:8080
# Juice Shop: http://localhost:3000
# WebGoat:    http://localhost:8081
```

## Usage

```python
from cybersentinel.core.orchestrator import Orchestrator
from cybersentinel.models.session import Session, SessionMode
from cybersentinel.models.finding import Finding, Severity

# Create a session with defined scope
session = Session(mode=SessionMode.GUIDED)
session.add_target("webapp.example.com", approved_by="your_name")

# Initialize orchestrator
orch = Orchestrator(session=session)
orch.validate_scope()

# Classify target and get dispatch plan
agents = orch.classify("infrastructure")
# Returns: ['config', 'dependency', 'threat_model', 'report']

# Add findings from sub-agents
finding = Finding(
    title="SQL Injection in Login",
    severity=Severity.CRITICAL,
    description="Unsanitized user input in login form",
    affected_component="/api/login",
    agent_source="sast",
    cve_ids=["CWE-89"],
    mitre_techniques=["T1190"],
    remediation="Use parameterized queries",
)
orch.add_finding(finding)

# Hit the mandatory checkpoint
print(orch.checkpoint())

# After human review
orch.approve_checkpoint(approved_by="your_name")
report = orch.generate_report()
```

## Project Structure

```
cybersentinel-agent/
├── cybersentinel/
│   ├── agents/          # Sub-agent definitions (SAST, Dependency, Config, etc.)
│   ├── core/
│   │   ├── safety.py    # Safety enforcement layer (validate_action)
│   │   └── orchestrator.py  # Central coordinator
│   ├── models/          # Session, Finding, Action data models
│   └── utils/
├── skill/               # CyberSentinel skill files (SKILL.md + references)
│   ├── SKILL.md
│   └── references/      # MITRE ATT&CK, CVE, IR, log analysis, etc.
├── tests/               # 30 tests covering all safety rules
├── demo/                # Demo script + Docker targets
├── docs/
└── pyproject.toml
```

## Roadmap

- [ ] Claude Agent SDK integration for AI-powered sub-agents
- [ ] MCP server connectors (VirusTotal, Shodan, NVD, CISA KEV)
- [ ] Live demo against DVWA/Juice Shop with automated findings
- [ ] Sigma rule generation pipeline
- [ ] STIX/TAXII threat intel feed integration
- [ ] Web dashboard for assessment management

## Ethics

This framework is defensive only. It will never generate exploit code, attack payloads, or offensive tooling. Every finding includes remediation. The safety rules are enforced in code and cannot be bypassed.

## License

MIT
