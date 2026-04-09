#!/usr/bin/env python3
"""Demo script — shows CyberSentinel's orchestrator and safety layer in action.

Run this to see:
1. Session creation with scope validation
2. Sub-agent dispatch
3. Safety rules blocking violations
4. Human checkpoint gate
5. Report generation after approval

No Docker or external services needed — this is a self-contained demo
using simulated findings.
"""

from cybersentinel.core.orchestrator import Orchestrator
from cybersentinel.core.safety import (
    ScopeViolation,
    HardStop,
    CredentialViolation,
    NetworkViolation,
)
from cybersentinel.models.action import Action, ActionType
from cybersentinel.models.finding import Finding, Severity
from cybersentinel.models.session import Session, SessionMode


def main():
    print("=" * 60)
    print("  CyberSentinel — Demo Session")
    print("=" * 60)
    print()

    # --- Step 1: Create session with scope ---
    print("[1] Creating session with defined scope...")
    session = Session(mode=SessionMode.GUIDED)
    session.add_target("juice-shop:3000", approved_by="Leishka")
    session.add_target("dvwa:8080", approved_by="Leishka")
    print(f"    Session ID: {session.id}")
    print(f"    Mode: {session.mode.value}")
    print(f"    Targets: {session.approved_targets}")
    print()

    # --- Step 2: Initialize orchestrator ---
    orch = Orchestrator(session=session)
    orch.validate_scope()
    print("[2] Scope validated ✓")
    print()

    # --- Step 3: Classify and dispatch ---
    agents = orch.classify("infrastructure")
    print(f"[3] Target classified as 'infrastructure'")
    print(f"    Dispatch plan: {' → '.join(agents)}")
    print()

    # --- Step 4: Simulate sub-agent findings ---
    print("[4] Sub-agents producing findings...")

    findings = [
        Finding(
            title="Directory Listing Enabled",
            severity=Severity.MEDIUM,
            description="Nginx autoindex is enabled, exposing directory contents to unauthenticated users.",
            affected_component="nginx.conf",
            agent_source="config",
            cwe_ids=["CWE-548"],
            mitre_techniques=["T1083"],
            remediation="Set 'autoindex off;' in the server block.",
            verification_steps="curl -I http://juice-shop:3000/ and verify no directory listing.",
        ),
        Finding(
            title="Missing Security Headers",
            severity=Severity.MEDIUM,
            description="X-Frame-Options, X-Content-Type-Options, and Content-Security-Policy headers are missing.",
            affected_component="HTTP response headers",
            agent_source="config",
            cwe_ids=["CWE-1021", "CWE-693"],
            mitre_techniques=["T1189"],
            remediation="Add security headers in nginx: X-Frame-Options DENY, X-Content-Type-Options nosniff, CSP.",
            verification_steps="curl -I http://juice-shop:3000/ and verify headers present.",
        ),
        Finding(
            title="SQL Injection in Search",
            severity=Severity.CRITICAL,
            description="The /rest/products/search endpoint is vulnerable to SQL injection via the 'q' parameter.",
            affected_component="/rest/products/search",
            agent_source="sast",
            cve_ids=["CVE-DEMO-001"],
            cwe_ids=["CWE-89"],
            cvss_score=9.8,
            mitre_tactics=["TA0001"],
            mitre_techniques=["T1190"],
            remediation="Use parameterized queries. Replace string concatenation with prepared statements.",
            detection_guidance="Monitor for SQL syntax in query parameters: UNION, SELECT, OR 1=1",
            verification_steps="Test with parameterized query and verify no injection.",
        ),
        Finding(
            title="Outdated Express.js (Known CVEs)",
            severity=Severity.HIGH,
            description="Express.js 4.17.1 has known vulnerabilities including prototype pollution.",
            affected_component="package.json → express",
            agent_source="dependency",
            cve_ids=["CVE-2024-29041"],
            cwe_ids=["CWE-1321"],
            cvss_score=7.5,
            mitre_techniques=["T1190"],
            remediation="Update to express@4.21.0 or later: npm install express@latest",
            verification_steps="npm list express — confirm version ≥ 4.21.0",
        ),
    ]

    for f in findings:
        orch.add_finding(f)
        print(f"    [{f.severity.value.upper()}] {f.title} (from {f.agent_source})")
    print()

    # --- Step 5: Safety demonstrations ---
    print("[5] Safety rule demonstrations...")
    print()

    # Rule 0: Scope violation
    print("    Testing scope enforcement...")
    try:
        from cybersentinel.core.safety import validate_action
        action = Action(
            type=ActionType.ANALYZE,
            agent_name="test",
            target="production-server.corp.com",
            description="Analyze production server",
        )
        validate_action("test", action, "production-server.corp.com", session)
    except ScopeViolation as e:
        print(f"    ✓ BLOCKED: {e.message}")
    print()

    # Rule 1: Destructive action
    print("    Testing destructive action block...")
    try:
        action = Action(
            type=ActionType.EXECUTE_WITH_APPROVAL,
            agent_name="test",
            target="juice-shop:3000",
            description="Drop database",
            is_destructive=True,
        )
        session.mode = SessionMode.ACTIVE  # Even in active mode...
        validate_action("test", action, "juice-shop:3000", session)
    except HardStop as e:
        print(f"    ✓ BLOCKED: {e.message}")
    session.mode = SessionMode.GUIDED  # Reset
    print()

    # Rule 2: Credential detection
    print("    Testing credential detection...")
    try:
        action = Action(
            type=ActionType.GENERATE_COMMANDS,
            agent_name="test",
            target="juice-shop:3000",
            description="API call",
            command="curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test'",
        )
        validate_action("test", action, "juice-shop:3000", session)
    except CredentialViolation as e:
        print(f"    ✓ BLOCKED: {e.message}")
    print()

    # Rule 3: Network request
    print("    Testing network request block...")
    try:
        action = Action(
            type=ActionType.ANALYZE,
            agent_name="test",
            target="juice-shop:3000",
            description="Port scan",
            requires_network=True,
        )
        validate_action("test", action, "juice-shop:3000", session)
    except NetworkViolation as e:
        print(f"    ✓ BLOCKED: {e.message}")
    print()

    # --- Step 6: Checkpoint ---
    print("[6] Human checkpoint gate...")
    orch.resolve_conflicts()
    checkpoint = orch.checkpoint()
    print(checkpoint)

    # --- Step 7: Human approves ---
    print("[7] Human approves checkpoint...")
    orch.approve_checkpoint(approved_by="Leishka")
    print("    Checkpoint approved ✓")
    print()

    # --- Step 8: Generate report ---
    print("[8] Generating report...")
    report = orch.generate_report()
    print()
    print(report)

    # --- Audit trail ---
    print()
    print(f"[AUDIT] Total log entries: {len(session.export_audit_log())}")
    print(f"[AUDIT] Total findings: {len(session.findings)} (immutable)")
    print()
    print("=" * 60)
    print("  Demo complete.")
    print("=" * 60)


if __name__ == "__main__":
    main()
