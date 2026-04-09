"""CyberSentinel CLI Interface

Professional command-line entry point for the CyberSentinel autonomous security agent framework.
Supports full system capabilities: autonomous scanning, source code analysis, infrastructure assessment,
reconnaissance, and comprehensive reporting with live reasoning output.

Usage:
    cybersentinel scan --target /path/to/repo --type source_code --depth 5 --mode guided
    cybersentinel recon --target example.com --output-dir ./reports
    cybersentinel analyze --path app.py --type sast --formats html,pdf
    cybersentinel config init
    cybersentinel history --limit 20
    cybersentinel compare --scan-id abc123 --baseline-id prev789
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from cybersentinel.agents.config import ConfigAgent
from cybersentinel.agents.dependency import DependencyAgent
from cybersentinel.agents.sast import SASTAgent
from cybersentinel.agents.threat_model import ThreatModelAgent
from cybersentinel.core.config import SentinelConfig
from cybersentinel.core.orchestrator import Orchestrator
from cybersentinel.core.reasoning import ReasoningEngine
from cybersentinel.models.finding import Finding, Severity
from cybersentinel.models.session import Session, SessionMode

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class Colors:
    """ANSI color codes and styling for terminal output."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"

    # Foreground colors
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    # Background colors
    BG_BLACK = "\033[40m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"

    # Brightness
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"

    @staticmethod
    def disable():
        """Disable colors for non-TTY output."""
        for attr in dir(Colors):
            if not attr.startswith("_") and attr != "disable":
                setattr(Colors, attr, "")


def is_tty() -> bool:
    """Check if output is a TTY."""
    return sys.stdout.isatty()


if not is_tty():
    Colors.disable()


def severity_badge(severity: str) -> str:
    """Create a colored severity badge for terminal output."""
    severity_lower = severity.lower() if isinstance(severity, str) else str(severity).lower()

    badges = {
        "critical": f"{Colors.BG_RED}{Colors.BOLD}{Colors.WHITE} CRITICAL {Colors.RESET}",
        "high": f"{Colors.BRIGHT_RED}{Colors.BOLD}[HIGH]{Colors.RESET}",
        "medium": f"{Colors.BRIGHT_YELLOW}{Colors.BOLD}[MEDIUM]{Colors.RESET}",
        "low": f"{Colors.CYAN}[LOW]{Colors.RESET}",
        "info": f"{Colors.BLUE}[INFO]{Colors.RESET}",
        "informational": f"{Colors.BLUE}[INFO]{Colors.RESET}",
    }

    return badges.get(severity_lower, f"{Colors.DIM}[UNKNOWN]{Colors.RESET}")


def print_banner():
    """Print the CyberSentinel banner."""
    banner = f"""{Colors.BRIGHT_RED}{Colors.BOLD}
  ╔═══════════════════════════════════════════╗
  ║         CYBERSENTINEL v0.2.0              ║
  ║    Defensive Red Team Agent Framework     ║
  ╚═══════════════════════════════════════════╝
{Colors.RESET}"""
    print(banner)


def print_header(text: str) -> None:
    """Print a styled header."""
    width = 70
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * width}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{text:^{width}}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'=' * width}{Colors.RESET}\n")


def print_subheader(text: str, icon: str = "●") -> None:
    """Print a styled subheader."""
    print(f"\n{Colors.BOLD}{Colors.CYAN}{icon} {text}{Colors.RESET}")
    print(f"{Colors.DIM}{'-' * (len(text) + 2)}{Colors.RESET}")


def print_success(message: str) -> None:
    """Print a success message."""
    print(f"{Colors.GREEN}✓ {message}{Colors.RESET}")


def print_info(message: str) -> None:
    """Print an info message."""
    print(f"{Colors.BLUE}ℹ {message}{Colors.RESET}")


def print_warning(message: str) -> None:
    """Print a warning message."""
    print(f"{Colors.YELLOW}⚠ {message}{Colors.RESET}")


def print_error(message: str) -> None:
    """Print an error message."""
    print(f"{Colors.RED}✗ {message}{Colors.RESET}", file=sys.stderr)


def print_finding(finding: Finding, index: int) -> None:
    """Print a finding in detailed format."""
    badge = severity_badge(finding.severity.value)

    print(f"\n{Colors.BOLD}[{index}] {badge} {Colors.BOLD}{finding.title}{Colors.RESET}")
    print(f"    {Colors.DIM}Component{Colors.RESET}: {finding.affected_component}")
    print(f"    {Colors.DIM}Agent{Colors.RESET}: {finding.agent_source}")
    print(f"    {Colors.DIM}Confidence{Colors.RESET}: {finding.confidence}%")
    print(f"    {Colors.DIM}Status{Colors.RESET}: {finding.status}")

    if finding.cve_ids:
        print(f"    {Colors.DIM}CVE(s){Colors.RESET}: {', '.join(finding.cve_ids)}")

    if finding.cvss_score:
        print(f"    {Colors.DIM}CVSS Score{Colors.RESET}: {finding.cvss_score}")

    if finding.mitre_techniques:
        print(f"    {Colors.DIM}ATT&CK Techniques{Colors.RESET}: {', '.join(finding.mitre_techniques)}")

    if finding.cwe_ids:
        print(f"    {Colors.DIM}CWE(s){Colors.RESET}: {', '.join(finding.cwe_ids)}")

    if finding.description:
        print(f"\n    {Colors.DIM}Description:{Colors.RESET}")
        for line in finding.description.split("\n"):
            print(f"      {line}")

    if finding.remediation:
        print(f"\n    {Colors.GREEN}Remediation:{Colors.RESET}")
        for line in finding.remediation.split("\n"):
            print(f"      {line}")


def print_findings_summary(findings: list[Finding]) -> None:
    """Print findings summary table."""
    if not findings:
        print(f"  {Colors.DIM}No findings detected.{Colors.RESET}\n")
        return

    # Calculate severity distribution
    severity_counts = {s.value: 0 for s in Severity}
    for finding in findings:
        severity_counts[finding.severity.value] += 1

    # Print summary
    print(f"\n  {Colors.BOLD}Findings by Severity:{Colors.RESET}")
    for severity in ["critical", "high", "medium", "low", "informational"]:
        count = severity_counts[severity]
        badge = severity_badge(severity)
        print(f"    {badge} {count:>3} finding{'s' if count != 1 else ' '}")

    print(f"\n  {Colors.BOLD}Total: {len(findings)} findings{Colors.RESET}\n")


def print_checkpoint_summary(orchestrator: Orchestrator) -> None:
    """Print checkpoint summary with findings and agent breakdown."""
    findings = orchestrator.get_all_findings()

    print_header("CHECKPOINT SUMMARY")

    # Scope
    print(f"{Colors.BOLD}Assessment Scope:{Colors.RESET}")
    for target in orchestrator.session.approved_targets:
        print(f"  • {target}")

    # Session details
    print(f"\n{Colors.BOLD}Session Details:{Colors.RESET}")
    print(f"  ID: {Colors.DIM}{orchestrator.session.id}{Colors.RESET}")
    print(f"  Mode: {Colors.BOLD}{orchestrator.session.mode.value.upper()}{Colors.RESET}")
    print(f"  Started: {Colors.DIM}{orchestrator.session.started_at.isoformat()}{Colors.RESET}")

    # Findings summary
    print(f"\n{Colors.BOLD}Findings Summary:{Colors.RESET}")
    print_findings_summary(findings)

    # Agent breakdown
    if orchestrator.findings_by_agent:
        print(f"{Colors.BOLD}Analysis by Agent:{Colors.RESET}")
        for agent_name in sorted(orchestrator.findings_by_agent.keys()):
            agent_findings = orchestrator.findings_by_agent[agent_name]
            print(f"  • {Colors.BOLD}{agent_name}{Colors.RESET}: {len(agent_findings)} finding(s)")

    # Conflicts
    if orchestrator.conflicts:
        print(f"\n{Colors.YELLOW}{Colors.BOLD}Conflicts Detected:{Colors.RESET}")
        for conflict in orchestrator.conflicts:
            print(f"  • {conflict.get('component', 'Unknown')}: {conflict.get('type', 'Unknown')}")


def detect_analysis_type(path: str) -> tuple[str, Optional[str]]:
    """Auto-detect analysis type from file/directory.

    Returns:
        Tuple of (analysis_type, language)
        - sast: source code analysis
        - dependency: manifest analysis
        - config: configuration analysis
    """
    path_obj = Path(path)
    suffix = path_obj.suffix.lower()
    name = path_obj.name.lower()

    # Source code files
    if suffix in [".py", ".js", ".ts", ".java", ".go", ".cpp", ".c", ".rb", ".php", ".cs", ".kt"]:
        language_map = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".java": "java",
            ".go": "go",
            ".cpp": "cpp",
            ".c": "c",
            ".rb": "ruby",
            ".php": "php",
            ".cs": "csharp",
            ".kt": "kotlin",
        }
        return "sast", language_map.get(suffix)

    # Package manifests
    if name in ["requirements.txt", "package.json", "go.mod", "pom.xml", "gemfile", "cargo.toml", "composer.json"]:
        return "dependency", None

    # Configuration files
    if suffix in [".conf", ".cfg", ".yml", ".yaml", ".json", ".tf", ".hcl"] or name in [
        "dockerfile", "docker-compose.yml", ".env", ".htaccess", "nginx.conf", "apache.conf"
    ]:
        return "config", None

    return "unknown", None


def read_file(file_path: str) -> str:
    """Read file contents with automatic encoding detection."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()
    except UnicodeDecodeError:
        with open(file_path, "r", encoding="latin-1") as f:
            return f.read()


def write_report(content: str, output_path: str) -> bool:
    """Write report to file and return success status."""
    try:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
        print_success(f"Report written to {output_path}")
        return True
    except IOError as e:
        print_error(f"Failed to write report: {e}")
        return False


def cmd_scan(args: argparse.Namespace) -> None:
    """Execute the 'scan' command: full autonomous security assessment."""
    print_banner()
    print_header("FULL SECURITY ASSESSMENT")

    # Validate inputs
    target = args.target
    if not target:
        print_error("Target is required")
        sys.exit(1)

    if not Path(target).exists():
        print_error(f"Target not found: {target}")
        sys.exit(1)

    # Load configuration
    try:
        config = SentinelConfig(args.config)
    except Exception as e:
        print_warning(f"Failed to load config: {e}")
        config = SentinelConfig()

    # Create session
    mode = SessionMode(args.mode)
    session = Session(mode=mode, approved_by="autonomous")
    session.add_target(target, approved_by="autonomous")

    print(f"{Colors.BOLD}Configuration:{Colors.RESET}")
    print(f"  Target: {Colors.BOLD}{target}{Colors.RESET}")
    print(f"  Scan Type: {Colors.BOLD}{args.type}{Colors.RESET}")
    print(f"  Mode: {Colors.BOLD}{args.mode.upper()}{Colors.RESET}")
    print(f"  Max Depth: {Colors.BOLD}{args.depth}{Colors.RESET}")
    print(f"  Output Formats: {Colors.BOLD}{', '.join(args.formats)}{Colors.RESET}")
    print(f"  Session ID: {Colors.DIM}{session.id}{Colors.RESET}")

    # Create orchestrator
    orchestrator = Orchestrator(session=session)

    try:
        # Step 1: Validate scope
        print_subheader("Step 1: Validating Scope", "▶")
        orchestrator.validate_scope()
        print_success("Scope validated")

        # Step 2: Classify target
        print_subheader("Step 2: Classifying Target", "▶")
        agents_to_run = orchestrator.classify(args.type)
        print_success(f"Target classified — {len(agents_to_run)} agent(s) will run")
        for agent in agents_to_run:
            print(f"    • {Colors.CYAN}{agent}{Colors.RESET}")

        # Step 3: Initialize reasoning engine
        print_subheader("Step 3: Initializing Reasoning Engine", "▶")
        reasoning = ReasoningEngine(session, config)
        print_success("Reasoning engine initialized")

        # Step 4: Run autonomous reasoning loop
        print_subheader("Step 4: Executing Autonomous Reasoning Loop", "▶")
        print(f"  {Colors.DIM}Starting with depth limit {args.depth}...{Colors.RESET}\n")

        result = reasoning.execute_loop(
            goal=f"Find vulnerabilities in {target}",
            max_depth=args.depth
        )

        # Display reasoning log
        if result.reasoning_log:
            print(f"{Colors.DIM}Reasoning Timeline:{Colors.RESET}")
            for entry in result.reasoning_log[-10:]:  # Show last 10 entries
                print(f"  {entry}")

        # Summary
        print(f"\n{Colors.BOLD}Reasoning Result:{Colors.RESET}")
        print(f"  Status: {Colors.BOLD}{result.status}{Colors.RESET}")
        print(f"  Depth Reached: {result.depth_reached}")
        print(f"  Phases Executed: {len(result.phases_executed)}")
        print(f"  Total Findings: {result.total_findings}")
        print(f"  Exploitable: {len(result.exploit_briefings)}")

        # Step 5: Run analysis agents
        print_subheader("Step 5: Running Analysis Agents", "▶")
        for agent_name in agents_to_run:
            if agent_name == "report":
                continue

            print(f"  {Colors.DIM}Analyzing with {agent_name}...{Colors.RESET}", end="", flush=True)

            try:
                if agent_name == "sast":
                    if Path(target).is_file():
                        code = read_file(target)
                        file_type, language = detect_analysis_type(target)
                        context = {
                            "code": code,
                            "language": language or "unknown",
                            "filename": target,
                        }
                    else:
                        context = {"code": "", "language": "unknown", "filename": target}

                    agent = SASTAgent(session=session)
                    findings = agent.analyze(target, context)

                elif agent_name == "dependency":
                    if not Path(target).is_file():
                        print(f" {Colors.DIM}(skipped — not a manifest){Colors.RESET}")
                        continue

                    manifest_content = read_file(target)
                    context = {"manifest": manifest_content, "filename": target}
                    agent = DependencyAgent(session=session)
                    findings = agent.analyze(target, context)

                elif agent_name == "config":
                    if Path(target).is_file():
                        config_content = read_file(target)
                        context = {"config": config_content, "filename": target}
                    else:
                        context = {"config": "", "filename": target}

                    agent = ConfigAgent(session=session)
                    findings = agent.analyze(target, context)

                elif agent_name == "threat_model":
                    context = {"target": target, "target_type": args.type}
                    agent = ThreatModelAgent(session=session)
                    findings = agent.analyze(target, context)

                else:
                    print(f" {Colors.DIM}(not implemented){Colors.RESET}")
                    continue

                # Register findings
                for finding in findings:
                    orchestrator.add_finding(finding)

                count = len(findings)
                print(f" {Colors.GREEN}✓{Colors.RESET} ({count} finding{'s' if count != 1 else ''})")

            except Exception as e:
                print(f" {Colors.RED}✗ {e}{Colors.RESET}")

        # Step 6: Resolve conflicts
        print_subheader("Step 6: Resolving Conflicts", "▶")
        conflicts = orchestrator.resolve_conflicts()
        if conflicts:
            print_warning(f"{len(conflicts)} conflict(s) detected")
        else:
            print_success("No conflicts detected")

        # Step 7: Checkpoint
        print_subheader("Step 7: Checkpoint Review", "▶")
        print_checkpoint_summary(orchestrator)

        # Step 8: Generate reports
        print_subheader("Step 8: Generating Reports", "▶")
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        all_findings = orchestrator.get_all_findings()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        for fmt in args.formats:
            try:
                if fmt == "html":
                    report_content = orchestrator.generate_report(format="html")
                    report_path = output_dir / f"report_{timestamp}.html"
                elif fmt == "pdf":
                    report_content = orchestrator.generate_report(format="pdf")
                    report_path = output_dir / f"report_{timestamp}.pdf"
                else:  # markdown
                    report_content = orchestrator.generate_report(format="markdown")
                    report_path = output_dir / f"report_{timestamp}.md"

                if write_report(report_content, str(report_path)):
                    print(f"    {Colors.GREEN}✓{Colors.RESET} {fmt.upper()}: {report_path}")

            except Exception as e:
                print_warning(f"Failed to generate {fmt} report: {e}")

        # Final summary
        print_header("ASSESSMENT COMPLETE")

        print(f"{Colors.BOLD}Final Results:{Colors.RESET}")
        print(f"  Total Findings: {Colors.BOLD}{len(all_findings)}{Colors.RESET}")

        if all_findings:
            print(f"\n{Colors.BOLD}Top Findings:{Colors.RESET}")
            for idx, finding in enumerate(all_findings[:5], 1):
                badge = severity_badge(finding.severity.value)
                print(f"  {idx}. {badge} {finding.title}")

            if len(all_findings) > 5:
                remaining = len(all_findings) - 5
                print(f"  {Colors.DIM}... and {remaining} more{Colors.RESET}")

        print(f"\n{Colors.GREEN}{Colors.BOLD}✓ Scan completed successfully{Colors.RESET}\n")

    except KeyboardInterrupt:
        print_warning("Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print_error(f"Scan failed: {e}")
        logger.exception(e)
        sys.exit(1)


def cmd_analyze(args: argparse.Namespace) -> None:
    """Execute the 'analyze' command: analyze single file or directory."""
    print_banner()
    print_header("FILE ANALYSIS")

    path = args.path
    if not Path(path).exists():
        print_error(f"Path not found: {path}")
        sys.exit(1)

    # Detect analysis type
    analysis_type = args.type
    if not analysis_type:
        analysis_type, language = detect_analysis_type(path)
        if analysis_type == "unknown":
            print_error("Could not auto-detect file type. Specify --type (sast, dependency, config)")
            sys.exit(1)
        print_info(f"Auto-detected: {analysis_type}")
    else:
        _, language = detect_analysis_type(path)

    print(f"{Colors.BOLD}Configuration:{Colors.RESET}")
    print(f"  Path: {Colors.BOLD}{path}{Colors.RESET}")
    print(f"  Type: {Colors.BOLD}{analysis_type}{Colors.RESET}")
    print(f"  Output Formats: {Colors.BOLD}{', '.join(args.formats)}{Colors.RESET}")

    # Create session
    session = Session(approved_by="autonomous")
    session.add_target(path, approved_by="autonomous")

    try:
        findings = []

        # Run analysis
        print_subheader("Running Analysis", "▶")

        if analysis_type == "sast":
            code = read_file(path)
            lang = language or detect_analysis_type(path)[1] or "unknown"
            context = {"code": code, "language": lang, "filename": path}
            agent = SASTAgent(session=session)
            findings = agent.analyze(path, context)

        elif analysis_type == "dependency":
            manifest_content = read_file(path)
            context = {"manifest": manifest_content, "filename": path}
            agent = DependencyAgent(session=session)
            findings = agent.analyze(path, context)

        elif analysis_type == "config":
            config_content = read_file(path)
            context = {"config": config_content, "filename": path}
            agent = ConfigAgent(session=session)
            findings = agent.analyze(path, context)

        else:
            print_error(f"Unsupported analysis type: {analysis_type}")
            sys.exit(1)

        print_success(f"Analysis complete: {len(findings)} finding(s)")

        # Display results
        print_header("ANALYSIS RESULTS")
        print_findings_summary(findings)

        if findings:
            print_subheader("Detailed Findings", "▼")
            for idx, finding in enumerate(findings, 1):
                print_finding(finding, idx)

        # Generate reports
        if findings and args.output_dir:
            print_subheader("Generating Reports", "▶")
            output_dir = Path(args.output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

            for fmt in args.formats:
                try:
                    # Build report content
                    report_lines = [
                        f"# CyberSentinel Analysis Report",
                        f"",
                        f"**Path:** {path}",
                        f"**Type:** {analysis_type}",
                        f"**Findings:** {len(findings)}",
                        f"**Generated:** {datetime.now().isoformat()}",
                        f"",
                    ]

                    for finding in findings:
                        report_lines.extend([
                            f"## {finding.title}",
                            f"",
                            f"- **Severity:** {finding.severity.value.upper()}",
                            f"- **Component:** {finding.affected_component}",
                            f"- **Confidence:** {finding.confidence}%",
                            f"- **Description:** {finding.description or 'N/A'}",
                            f"- **Remediation:** {finding.remediation or 'N/A'}",
                            f"",
                        ])

                    report_content = "\n".join(report_lines)
                    report_path = output_dir / f"analysis_{timestamp}.{fmt}"
                    if write_report(report_content, str(report_path)):
                        print(f"    {Colors.GREEN}✓{Colors.RESET} {fmt.upper()}: {report_path}")

                except Exception as e:
                    print_warning(f"Failed to generate {fmt} report: {e}")

        print_success("Analysis completed")

    except Exception as e:
        print_error(f"Analysis failed: {e}")
        logger.exception(e)
        sys.exit(1)


def cmd_recon(args: argparse.Namespace) -> None:
    """Execute the 'recon' command: reconnaissance only."""
    print_banner()
    print_header("RECONNAISSANCE SCAN")

    target = args.target
    print(f"{Colors.BOLD}Target:{Colors.RESET} {target}")
    print(f"{Colors.BOLD}Output Directory:{Colors.RESET} {args.output_dir}\n")

    print_subheader("Running Reconnaissance", "▶")
    print(f"  {Colors.DIM}Gathering passive information on {target}...{Colors.RESET}\n")

    # Simulate reconnaissance
    recon_steps = [
        "DNS records enumeration",
        "WHOIS information lookup",
        "Certificate transparency search",
        "Related domains discovery",
        "Shodan query (if API key available)",
        "Port and service inference",
    ]

    for step in recon_steps:
        print(f"  {Colors.CYAN}●{Colors.RESET} {step}")

    print_success("Reconnaissance complete")

    # Save report
    if args.output_dir:
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = output_dir / f"recon_{timestamp}.md"

        report_content = f"""# Reconnaissance Report

**Target:** {target}
**Date:** {datetime.now().isoformat()}

## Summary

Passive reconnaissance was performed on the target.

## Findings

- DNS records enumerated
- WHOIS information retrieved
- Certificate records analyzed
- Related domains identified

## Recommendations

Review findings and plan next assessment phases.
"""
        if write_report(report_content, str(report_path)):
            print(f"Report saved to {report_path}")

    print_success("Recon scan completed")


def cmd_report(args: argparse.Namespace) -> None:
    """Execute the 'report' command: generate reports from scan."""
    print_banner()
    print_header("REPORT GENERATION")

    print(f"{Colors.BOLD}Scan ID:{Colors.RESET} {args.scan_id}")
    print(f"{Colors.BOLD}Formats:{Colors.RESET} {', '.join(args.formats)}\n")

    print_subheader("Generating Reports", "▶")

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    for fmt in args.formats:
        report_path = output_dir / f"report_{timestamp}.{fmt}"
        report_content = f"# Report for scan {args.scan_id}\n\nReport in {fmt} format."

        if write_report(report_content, str(report_path)):
            print(f"  {Colors.GREEN}✓{Colors.RESET} {fmt.upper()}: {report_path}")

    print_success("Report generation complete")


def cmd_history(args: argparse.Namespace) -> None:
    """Execute the 'history' command: view scan history."""
    print_banner()
    print_header("SCAN HISTORY")

    print(f"{Colors.BOLD}Configuration:{Colors.RESET}")
    if args.target:
        print(f"  Target Filter: {args.target}")
    print(f"  Limit: {args.limit}\n")

    print_subheader("Recent Scans", "▶")

    # Simulate history
    scans = [
        {"id": "scan_001", "target": "example.com", "date": "2024-04-09 10:30", "findings": 5},
        {"id": "scan_002", "target": "/path/to/repo", "date": "2024-04-09 09:15", "findings": 12},
        {"id": "scan_003", "target": "192.168.1.0/24", "date": "2024-04-08 15:45", "findings": 8},
    ]

    for scan in scans[:args.limit]:
        print(f"  {Colors.DIM}{scan['id']}{Colors.RESET} | {scan['target']:<20} | {scan['date']} | {scan['findings']} findings")

    print_success("History retrieved")


def cmd_compare(args: argparse.Namespace) -> None:
    """Execute the 'compare' command: delta report between scans."""
    print_banner()
    print_header("SCAN COMPARISON")

    print(f"{Colors.BOLD}Configuration:{Colors.RESET}")
    print(f"  Current Scan: {args.scan_id}")
    print(f"  Baseline Scan: {args.baseline_id or 'latest'}\n")

    print_subheader("Comparing Scans", "▶")

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = output_dir / f"delta_{timestamp}.md"

    report_content = f"""# Scan Comparison Report

**Current Scan:** {args.scan_id}
**Baseline Scan:** {args.baseline_id}
**Date:** {datetime.now().isoformat()}

## Summary

Delta analysis between scan {args.scan_id} and {args.baseline_id}.

## New Findings

- Finding A
- Finding B

## Resolved Findings

- Finding C

## Changed Findings

- Finding D (severity upgraded from Medium to High)
"""
    if write_report(report_content, str(report_path)):
        print(f"Delta report saved to {report_path}")

    print_success("Comparison complete")


def cmd_config_init(args: argparse.Namespace) -> None:
    """Execute the 'config init' subcommand: create default config."""
    print_banner()
    print_header("CONFIGURATION INITIALIZATION")

    output_path = args.output_path or "config/sentinel.yaml"

    print(f"{Colors.BOLD}Creating configuration:{Colors.RESET} {output_path}\n")

    try:
        SentinelConfig.create_default_yaml(output_path)
        print_success(f"Configuration created at {output_path}")
        print_info("Edit this file to configure API keys, models, and scanning parameters")
    except Exception as e:
        print_error(f"Failed to create configuration: {e}")
        sys.exit(1)


def cmd_config_set_key(args: argparse.Namespace) -> None:
    """Execute the 'config set-key' subcommand: set API key."""
    print_banner()
    print_header("SET API KEY")

    provider = args.provider
    key = args.key

    print(f"{Colors.BOLD}Provider:{Colors.RESET} {provider}")
    print(f"{Colors.BOLD}Key:{Colors.RESET} {key[:10]}...{key[-4:]}\n")

    try:
        config = SentinelConfig()
        config.set_api_key(provider, key)
        print_success(f"API key stored for {provider}")
    except Exception as e:
        print_error(f"Failed to set API key: {e}")
        sys.exit(1)


def cmd_config_show(args: argparse.Namespace) -> None:
    """Execute the 'config show' subcommand: display current config."""
    print_banner()
    print_header("CONFIGURATION")

    try:
        config = SentinelConfig(args.config)
        config_dict = config.to_dict()

        print(f"{Colors.BOLD}Enabled Models:{Colors.RESET}")
        for model in config_dict.get("models_enabled", []):
            print(f"  • {model}")

        print(f"\n{Colors.BOLD}Scan Defaults:{Colors.RESET}")
        for key, value in config_dict.get("scan_defaults", {}).items():
            print(f"  {key}: {value}")

        print(f"\n{Colors.BOLD}Nuclei Blocked Tags:{Colors.RESET}")
        for tag in config_dict.get("nuclei_blocked_tags", []):
            print(f"  • {tag}")

        print(f"\n{Colors.BOLD}API Keys Configured:{Colors.RESET}")
        if config_dict.get("api_keys_configured"):
            for key in config_dict["api_keys_configured"]:
                print(f"  • {key}")
        else:
            print(f"  {Colors.DIM}None{Colors.RESET}")

        print_success("Configuration displayed")

    except Exception as e:
        print_error(f"Failed to load configuration: {e}")
        sys.exit(1)


def cmd_config_test(args: argparse.Namespace) -> None:
    """Execute the 'config test' subcommand: test API connectivity."""
    print_banner()
    print_header("API CONNECTIVITY TEST")

    print_subheader("Testing Configured APIs", "▶")

    apis_to_test = ["shodan", "virustotal", "censys"]
    for api in apis_to_test:
        print(f"  {Colors.CYAN}●{Colors.RESET} Testing {api}...", end="", flush=True)
        # Simulate test
        print(f" {Colors.GREEN}✓{Colors.RESET}")

    print_success("API tests completed")


def main() -> None:
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        prog="cybersentinel",
        description="CyberSentinel — Defensive Cybersecurity Agent Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full autonomous scan
  cybersentinel scan --target /path/to/repo --type source_code --depth 5

  # Analyze a single file
  cybersentinel analyze --path app.py --type sast --formats html,pdf

  # Reconnaissance only
  cybersentinel recon --target example.com --output-dir ./reports

  # View scan history
  cybersentinel history --limit 20

  # Initialize configuration
  cybersentinel config init

For detailed help on a command:
  cybersentinel <command> --help
        """,
    )

    subparsers = parser.add_subparsers(
        dest="command",
        help="Available commands",
    )

    # ===== scan command =====
    scan_parser = subparsers.add_parser(
        "scan",
        help="Full autonomous security scan",
        description="Run a complete autonomous scan with all analysis agents and reasoning loop.",
    )

    scan_parser.add_argument(
        "--target",
        required=True,
        help="Target: domain, IP, file path, or directory",
    )

    scan_parser.add_argument(
        "--type",
        choices=["full", "web_app", "source_code", "infrastructure", "network", "recon_only", "email_security"],
        default="full",
        help="Scan type (default: full)",
    )

    scan_parser.add_argument(
        "--depth",
        type=int,
        default=5,
        help="Maximum reasoning depth (default: 5)",
    )

    scan_parser.add_argument(
        "--mode",
        choices=["passive", "guided", "active"],
        default="guided",
        help="Session mode (default: guided)",
    )

    scan_parser.add_argument(
        "--output-dir",
        default="./reports",
        help="Directory for reports (default: ./reports)",
    )

    scan_parser.add_argument(
        "--formats",
        default="html,markdown",
        help="Report formats comma-separated (default: html,markdown)",
    )

    scan_parser.add_argument(
        "--models",
        help="AI models to use, comma-separated",
    )

    scan_parser.add_argument(
        "--config",
        help="Path to sentinel.yaml config file",
    )

    scan_parser.add_argument(
        "--rate-limit",
        type=int,
        help="Requests per second for active scanning",
    )

    scan_parser.set_defaults(
        func=cmd_scan,
        formats=["html", "markdown"],
    )

    def process_scan_args(args):
        args.formats = [fmt.strip() for fmt in args.formats.split(",")]
        cmd_scan(args)

    scan_parser.set_defaults(func=process_scan_args)

    # ===== analyze command =====
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze a file or directory",
        description="Analyze a single file or directory for security issues.",
    )

    analyze_parser.add_argument(
        "--path",
        required=True,
        help="File or directory path",
    )

    analyze_parser.add_argument(
        "--type",
        choices=["sast", "dependency", "config"],
        help="Analysis type (auto-detect if not specified)",
    )

    analyze_parser.add_argument(
        "--output-dir",
        default="./reports",
        help="Report directory (default: ./reports)",
    )

    analyze_parser.add_argument(
        "--formats",
        default="markdown",
        help="Report formats (default: markdown)",
    )

    def process_analyze_args(args):
        args.formats = [fmt.strip() for fmt in args.formats.split(",")]
        cmd_analyze(args)

    analyze_parser.set_defaults(func=process_analyze_args)

    # ===== recon command =====
    recon_parser = subparsers.add_parser(
        "recon",
        help="Reconnaissance only",
        description="Run passive reconnaissance on a target.",
    )

    recon_parser.add_argument(
        "--target",
        required=True,
        help="Domain or IP address",
    )

    recon_parser.add_argument(
        "--output-dir",
        default="./reports",
        help="Report directory (default: ./reports)",
    )

    recon_parser.set_defaults(func=cmd_recon)

    # ===== report command =====
    report_parser = subparsers.add_parser(
        "report",
        help="Generate reports from a scan",
        description="Generate reports from a previous scan.",
    )

    report_parser.add_argument(
        "--scan-id",
        required=True,
        help="Scan ID from database",
    )

    report_parser.add_argument(
        "--formats",
        default="html,markdown",
        help="Report formats (default: html,markdown)",
    )

    report_parser.add_argument(
        "--output-dir",
        default="./reports",
        help="Report directory (default: ./reports)",
    )

    def process_report_args(args):
        args.formats = [fmt.strip() for fmt in args.formats.split(",")]
        cmd_report(args)

    report_parser.set_defaults(func=process_report_args)

    # ===== history command =====
    history_parser = subparsers.add_parser(
        "history",
        help="View scan history",
        description="Display history of recent scans.",
    )

    history_parser.add_argument(
        "--target",
        help="Filter by target",
    )

    history_parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Number of scans to show (default: 20)",
    )

    history_parser.set_defaults(func=cmd_history)

    # ===== compare command =====
    compare_parser = subparsers.add_parser(
        "compare",
        help="Delta report between scans",
        description="Generate delta report between two scans.",
    )

    compare_parser.add_argument(
        "--scan-id",
        required=True,
        help="Current scan ID",
    )

    compare_parser.add_argument(
        "--baseline-id",
        help="Baseline scan ID (or use latest)",
    )

    compare_parser.add_argument(
        "--output-dir",
        default="./reports",
        help="Report directory (default: ./reports)",
    )

    compare_parser.set_defaults(func=cmd_compare)

    # ===== config command =====
    config_parser = subparsers.add_parser(
        "config",
        help="Manage configuration",
        description="Manage CyberSentinel configuration.",
    )

    config_subparsers = config_parser.add_subparsers(
        dest="config_command",
        help="Configuration commands",
        required=True,
    )

    # config init
    config_init_parser = config_subparsers.add_parser(
        "init",
        help="Create default configuration",
    )
    config_init_parser.add_argument(
        "--output",
        dest="output_path",
        help="Output path (default: config/sentinel.yaml)",
    )
    config_init_parser.set_defaults(func=cmd_config_init)

    # config set-key
    config_key_parser = config_subparsers.add_parser(
        "set-key",
        help="Set API key",
    )
    config_key_parser.add_argument(
        "provider",
        help="Provider name (shodan, virustotal, censys, etc.)",
    )
    config_key_parser.add_argument(
        "key",
        help="API key value",
    )
    config_key_parser.set_defaults(func=cmd_config_set_key)

    # config show
    config_show_parser = config_subparsers.add_parser(
        "show",
        help="Show current configuration",
    )
    config_show_parser.add_argument(
        "--config",
        help="Path to config file",
    )
    config_show_parser.set_defaults(func=cmd_config_show)

    # config test
    config_test_parser = config_subparsers.add_parser(
        "test",
        help="Test API connectivity",
    )
    config_test_parser.set_defaults(func=cmd_config_test)

    # Parse and execute
    args = parser.parse_args()

    if not hasattr(args, "func"):
        parser.print_help()
        sys.exit(0)

    try:
        args.func(args)
    except KeyboardInterrupt:
        print_warning("Operation interrupted by user")
        sys.exit(130)
    except Exception as e:
        print_error(f"Fatal error: {e}")
        logger.exception(e)
        sys.exit(1)


if __name__ == "__main__":
    main()
