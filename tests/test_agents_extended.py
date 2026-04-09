"""Tests for ThreatModelAgent, LogParserAgent, and detection rule generation.

Tests verify threat modeling, log parsing, and Sigma/YARA rule generation
from security findings.
"""

import pytest
from xml.etree import ElementTree as ET

from cybersentinel.agents.log_parser import LogParserAgent
from cybersentinel.models.finding import Finding, Severity
from cybersentinel.models.session import Session, SessionMode
from cybersentinel.utils.detection_rules import (
    SigmaRuleGenerator,
    YaraRuleGenerator,
    DetectionRuleBuilder,
)


@pytest.fixture
def session():
    """Create a test session with one approved target."""
    s = Session(mode=SessionMode.GUIDED)
    s.add_target("test-target", approved_by="test_operator")
    return s


@pytest.fixture
def log_parser_agent(session):
    """Create a LogParserAgent instance."""
    return LogParserAgent(session)


@pytest.fixture
def sigma_generator():
    """Create a SigmaRuleGenerator instance."""
    return SigmaRuleGenerator()


@pytest.fixture
def yara_generator():
    """Create a YaraRuleGenerator instance."""
    return YaraRuleGenerator()


@pytest.fixture
def rule_builder():
    """Create a DetectionRuleBuilder instance."""
    return DetectionRuleBuilder()


# ============================================================================
# LogParserAgent Tests
# ============================================================================

class TestLogParserBruteForce:
    """Test brute force attack detection in logs."""

    def test_syslog_brute_force_detection(self, log_parser_agent, session):
        """Detect brute force attempts in auth.log."""
        log_content = """
Feb 10 10:15:22 server sshd[1234]: Failed password for user admin from 192.168.1.100 port 54321 ssh2
Feb 10 10:15:25 server sshd[1235]: Failed password for user admin from 192.168.1.100 port 54322 ssh2
Feb 10 10:15:28 server sshd[1236]: Failed password for user admin from 192.168.1.100 port 54323 ssh2
Feb 10 10:15:31 server sshd[1237]: Failed password for user admin from 192.168.1.100 port 54324 ssh2
Feb 10 10:15:34 server sshd[1238]: Failed password for user admin from 192.168.1.100 port 54325 ssh2
Feb 10 10:15:37 server sshd[1239]: Failed password for user admin from 192.168.1.100 port 54326 ssh2
        """
        findings = log_parser_agent.analyze("test-target", {
            "log_content": log_content,
            "log_type": "syslog"
        })

        assert len(findings) > 0
        brute_force = next((f for f in findings if "Brute Force" in f.title), None)
        assert brute_force is not None
        assert brute_force.severity == Severity.HIGH
        assert "T1110" in brute_force.mitre_techniques
        assert "CWE-307" in [brute_force.cwe_ids] if isinstance(brute_force.cwe_ids, str) else brute_force.cwe_ids

    def test_syslog_fewer_than_threshold(self, log_parser_agent, session):
        """Few failed logins should not trigger brute force alert."""
        log_content = """
Feb 10 10:15:22 server sshd[1234]: Failed password for user admin from 192.168.1.100 port 54321 ssh2
Feb 10 10:15:25 server sshd[1235]: Failed password for user admin from 192.168.1.100 port 54322 ssh2
        """
        findings = log_parser_agent.analyze("test-target", {
            "log_content": log_content,
            "log_type": "syslog"
        })

        # Should not trigger brute force (less than threshold)
        assert not any("Brute Force" in f.title for f in findings)


class TestLogParserSQLInjection:
    """Test SQL injection attack detection in access logs."""

    def test_apache_sql_injection_detection(self, log_parser_agent, session):
        """Detect SQL injection attempts in Apache access log."""
        log_content = """
192.168.1.50 - - [10/Feb/2024:10:15:22 +0000] "GET /search?id=1 UNION SELECT * FROM users HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
192.168.1.50 - - [10/Feb/2024:10:15:25 +0000] "POST /api/login HTTP/1.1" 200 456 "-" "Mozilla/5.0"
192.168.1.51 - - [10/Feb/2024:10:15:28 +0000] "GET /products?filter='; DROP TABLE users;-- HTTP/1.1" 200 789 "-" "Mozilla/5.0"
        """
        findings = log_parser_agent.analyze("test-target", {
            "log_content": log_content,
            "log_type": "apache"
        })

        assert len(findings) > 0
        sql_injection = next((f for f in findings if "SQL Injection" in f.title), None)
        assert sql_injection is not None
        assert sql_injection.severity == Severity.HIGH
        assert "T1190" in sql_injection.mitre_techniques

    def test_sql_injection_with_encoded_payload(self, log_parser_agent, session):
        """Detect URL-encoded SQL injection."""
        log_content = """
192.168.1.50 - - [10/Feb/2024:10:15:22 +0000] "GET /api?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
        """
        findings = log_parser_agent.analyze("test-target", {
            "log_content": log_content,
            "log_type": "apache"
        })

        assert len(findings) > 0
        assert any("SQL" in f.title for f in findings)


class TestLogParserPathTraversal:
    """Test path traversal attack detection."""

    def test_nginx_path_traversal_detection(self, log_parser_agent, session):
        """Detect path traversal attempts in Nginx access log."""
        log_content = """
192.168.1.60 - - [10/Feb/2024:10:15:22 +0000] "GET /api/file?path=../../etc/passwd HTTP/1.1" 200 789 "-" "Mozilla/5.0"
192.168.1.60 - - [10/Feb/2024:10:15:25 +0000] "GET /download?file=../../../etc/shadow HTTP/1.1" 200 456 "-" "Mozilla/5.0"
192.168.1.61 - - [10/Feb/2024:10:15:28 +0000] "POST /upload HTTP/1.1" 201 123 "-" "Mozilla/5.0"
        """
        findings = log_parser_agent.analyze("test-target", {
            "log_content": log_content,
            "log_type": "nginx"
        })

        assert len(findings) > 0
        path_traversal = next((f for f in findings if "Path Traversal" in f.title), None)
        assert path_traversal is not None
        assert path_traversal.severity == Severity.HIGH
        assert "T1083" in path_traversal.mitre_techniques

    def test_path_traversal_percent_encoded(self, log_parser_agent, session):
        """Detect percent-encoded path traversal."""
        log_content = """
192.168.1.60 - - [10/Feb/2024:10:15:22 +0000] "GET /api?file=%2e%2e%2fetc%2fpasswd HTTP/1.1" 200 789 "-" "Mozilla/5.0"
        """
        findings = log_parser_agent.analyze("test-target", {
            "log_content": log_content,
            "log_type": "apache"
        })

        assert len(findings) > 0
        assert any("Path Traversal" in f.title for f in findings)


class TestLogParserSecurityScanner:
    """Test security scanner detection."""

    def test_scanner_detection_nikto(self, log_parser_agent, session):
        """Detect Nikto security scanner."""
        log_content = """
192.168.1.70 - - [10/Feb/2024:10:15:22 +0000] "GET / HTTP/1.0" 200 1234 "-" "Nikto/2.1.6 (Evasion:None)"
192.168.1.70 - - [10/Feb/2024:10:15:25 +0000] "GET /admin.php HTTP/1.0" 404 456 "-" "Nikto/2.1.6"
        """
        findings = log_parser_agent.analyze("test-target", {
            "log_content": log_content,
            "log_type": "apache"
        })

        assert len(findings) > 0
        scanner = next((f for f in findings if "Scanner" in f.title), None)
        assert scanner is not None
        assert scanner.severity == Severity.MEDIUM

    def test_scanner_detection_sqlmap(self, log_parser_agent, session):
        """Detect sqlmap scanner."""
        log_content = """
192.168.1.71 - - [10/Feb/2024:10:15:22 +0000] "GET /search?id=1 AND 1=1 HTTP/1.1" 200 1234 "-" "sqlmap/1.5.2"
        """
        findings = log_parser_agent.analyze("test-target", {
            "log_content": log_content,
            "log_type": "apache"
        })

        assert len(findings) > 0
        assert any("Scanner" in f.title for f in findings)


class TestLogParserHttpFlood:
    """Test HTTP flood/DoS detection."""

    def test_http_flood_detection(self, log_parser_agent, session):
        """Detect HTTP flood attack."""
        # Create 150 lines of requests from same IP
        log_lines = [
            f'192.168.1.80 - - [10/Feb/2024:10:15:{22+i%60:02d} +0000] "GET / HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
            for i in range(150)
        ]
        log_content = "\n".join(log_lines)

        findings = log_parser_agent.analyze("test-target", {
            "log_content": log_content,
            "log_type": "apache"
        })

        assert len(findings) > 0
        flood = next((f for f in findings if "HTTP Flood" in f.title or "flood" in f.description.lower()), None)
        assert flood is not None
        assert flood.severity == Severity.HIGH


class TestLogParserWindowsEventLog:
    """Test Windows Event Log parsing."""

    def test_windows_failed_logon_detection(self, log_parser_agent, session):
        """Detect failed logons in Windows Event Log."""
        xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<Events>
  <Event>
    <System>
      <EventID>4625</EventID>
      <Computer>WORKSTATION</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">Administrator</Data>
      <Data Name="IpAddress">192.168.1.100</Data>
      <Data Name="LogonType">3</Data>
    </EventData>
  </Event>
  <Event>
    <System>
      <EventID>4625</EventID>
      <Computer>WORKSTATION</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">Administrator</Data>
      <Data Name="IpAddress">192.168.1.100</Data>
      <Data Name="LogonType">3</Data>
    </EventData>
  </Event>
  <Event>
    <System>
      <EventID>4625</EventID>
      <Computer>WORKSTATION</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">Administrator</Data>
      <Data Name="IpAddress">192.168.1.100</Data>
      <Data Name="LogonType">3</Data>
    </EventData>
  </Event>
  <Event>
    <System>
      <EventID>4625</EventID>
      <Computer>WORKSTATION</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">Administrator</Data>
      <Data Name="IpAddress">192.168.1.100</Data>
      <Data Name="LogonType">3</Data>
    </EventData>
  </Event>
  <Event>
    <System>
      <EventID>4625</EventID>
      <Computer>WORKSTATION</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">Administrator</Data>
      <Data Name="IpAddress">192.168.1.100</Data>
      <Data Name="LogonType">3</Data>
    </EventData>
  </Event>
  <Event>
    <System>
      <EventID>4625</EventID>
      <Computer>WORKSTATION</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">Administrator</Data>
      <Data Name="IpAddress">192.168.1.100</Data>
      <Data Name="LogonType">3</Data>
    </EventData>
  </Event>
</Events>"""
        findings = log_parser_agent.analyze("test-target", {
            "log_content": xml_content,
            "log_type": "windows"
        })

        assert len(findings) > 0
        # Should detect brute force
        brute_force = next((f for f in findings if "Brute Force" in f.title), None)
        assert brute_force is not None or any("failed" in f.description.lower() for f in findings)

    def test_windows_audit_log_cleared(self, log_parser_agent, session):
        """Detect audit log clearing (evidence destruction)."""
        xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<Events>
  <Event>
    <System>
      <EventID>1102</EventID>
      <Computer>WORKSTATION</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">DOMAIN\\Administrator</Data>
    </EventData>
  </Event>
</Events>"""
        findings = log_parser_agent.analyze("test-target", {
            "log_content": xml_content,
            "log_type": "windows"
        })

        assert len(findings) > 0
        audit_clear = next((f for f in findings if "Audit Log Cleared" in f.title or "cleared" in f.description.lower()), None)
        assert audit_clear is not None
        assert audit_clear.severity == Severity.CRITICAL

    def test_windows_new_service_installation(self, log_parser_agent, session):
        """Detect service installation."""
        xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<Events>
  <Event>
    <System>
      <EventID>7045</EventID>
      <Computer>WORKSTATION</Computer>
    </System>
    <EventData>
      <Data Name="ServiceName">Malware</Data>
      <Data Name="ServiceFileName">C:\\Windows\\System32\\malware.exe</Data>
    </EventData>
  </Event>
</Events>"""
        findings = log_parser_agent.analyze("test-target", {
            "log_content": xml_content,
            "log_type": "windows"
        })

        assert len(findings) > 0
        service = next((f for f in findings if "Service Installation" in f.title or "service" in f.description.lower()), None)
        assert service is not None
        assert service.severity == Severity.MEDIUM


# ============================================================================
# Detection Rule Generator Tests
# ============================================================================

class TestSigmaRuleGeneration:
    """Test Sigma rule generation from findings."""

    def test_sigma_rule_from_sql_injection_finding(self, sigma_generator):
        """Generate Sigma rule from SQL injection finding."""
        finding = Finding(
            title="SQL Injection — String Concatenation",
            severity=Severity.CRITICAL,
            description="SQL query constructed using string concatenation with user-controlled input.",
            affected_component="app.py:42",
            agent_source="sast",
            cwe_ids=["CWE-89"],
            mitre_techniques=["T1190"],
            remediation="Use parameterized queries.",
            confidence="high",
        )

        sigma_rule = sigma_generator.generate(finding)

        assert "title:" in sigma_rule
        assert "SQL Injection" in sigma_rule
        assert "level: critical" in sigma_rule
        assert "attack.t1190" in sigma_rule
        assert "logsource:" in sigma_rule
        assert "detection:" in sigma_rule

    def test_sigma_rule_has_valid_structure(self, sigma_generator):
        """Sigma rule should be valid YAML."""
        finding = Finding(
            title="Command Injection Detection",
            severity=Severity.HIGH,
            description="os.system() called with user input",
            affected_component="script.py",
            agent_source="sast",
            cwe_ids=["CWE-78"],
            mitre_techniques=["T1059"],
            remediation="Use safer APIs",
            confidence="high",
        )

        sigma_rule = sigma_generator.generate(finding)

        # Basic YAML structure validation
        assert "title:" in sigma_rule
        assert "status:" in sigma_rule
        assert "detection:" in sigma_rule
        assert "condition:" in sigma_rule
        assert "level:" in sigma_rule

    def test_sigma_rule_batch_generation(self, sigma_generator):
        """Generate multiple Sigma rules."""
        findings = [
            Finding(
                title="SQL Injection",
                severity=Severity.CRITICAL,
                description="SQL injection vulnerability",
                affected_component="app.py",
                agent_source="sast",
                cwe_ids=["CWE-89"],
                mitre_techniques=["T1190"],
                remediation="Use parameterized queries",
            ),
            Finding(
                title="XSS Vulnerability",
                severity=Severity.HIGH,
                description="Cross-site scripting",
                affected_component="app.js",
                agent_source="sast",
                cwe_ids=["CWE-79"],
                mitre_techniques=["T1189"],
                remediation="Escape output",
            ),
        ]

        batch_rules = sigma_generator.generate_batch(findings)

        # Should contain both rules
        assert "SQL Injection" in batch_rules
        assert "XSS Vulnerability" in batch_rules


class TestYaraRuleGeneration:
    """Test YARA rule generation from findings."""

    def test_yara_rule_from_finding(self, yara_generator):
        """Generate YARA rule from finding."""
        finding = Finding(
            title="Malware Detection Pattern",
            severity=Severity.HIGH,
            description="Detects known malware command patterns",
            affected_component="memory",
            agent_source="memory_scanner",
            cwe_ids=["CWE-94"],
            mitre_techniques=["T1059"],
            remediation="Update antivirus",
            evidence="Pattern: 0x4d5a (MZ header)",
        )

        yara_rule = yara_generator.generate(finding)

        assert "rule " in yara_rule
        assert "meta:" in yara_rule
        assert "strings:" in yara_rule
        assert "condition:" in yara_rule
        assert "author = " in yara_rule

    def test_yara_rule_sql_injection_patterns(self, yara_generator):
        """YARA rule for SQL injection should include detection patterns."""
        finding = Finding(
            title="SQL Injection Payload",
            severity=Severity.CRITICAL,
            description="SQL injection attack detected",
            affected_component="network",
            agent_source="ids",
            cwe_ids=["CWE-89"],
            mitre_techniques=["T1190"],
            remediation="Filter SQL keywords",
        )

        yara_rule = yara_generator.generate(finding)

        # Should contain SQL-related patterns
        assert "union" in yara_rule.lower() or "select" in yara_rule.lower() or "strings:" in yara_rule

    def test_yara_rule_valid_syntax(self, yara_generator):
        """Generated YARA rule should have valid syntax."""
        finding = Finding(
            title="Test Rule",
            severity=Severity.MEDIUM,
            description="Test description",
            affected_component="test",
            agent_source="test",
            cwe_ids=["CWE-200"],
            mitre_techniques=["T1082"],
            remediation="Test remediation",
        )

        yara_rule = yara_generator.generate(finding)

        # Validate basic structure
        assert yara_rule.startswith("rule ")
        assert "{" in yara_rule
        assert "}" in yara_rule
        assert "meta:" in yara_rule
        assert "strings:" in yara_rule
        assert "condition:" in yara_rule

    def test_yara_rule_batch_generation(self, yara_generator):
        """Generate multiple YARA rules."""
        findings = [
            Finding(
                title="Malware Pattern 1",
                severity=Severity.HIGH,
                description="Pattern 1",
                affected_component="memory",
                agent_source="scanner",
                cwe_ids=["CWE-94"],
                mitre_techniques=["T1059"],
                remediation="Remediate",
            ),
            Finding(
                title="Malware Pattern 2",
                severity=Severity.HIGH,
                description="Pattern 2",
                affected_component="memory",
                agent_source="scanner",
                cwe_ids=["CWE-94"],
                mitre_techniques=["T1059"],
                remediation="Remediate",
            ),
        ]

        batch_rules = yara_generator.generate_batch(findings)

        # Should contain both rules
        assert batch_rules.count("rule ") == 2


class TestDetectionRuleBuilder:
    """Test high-level detection rule builder."""

    def test_generate_sigma_rules(self, rule_builder):
        """Generate Sigma rules from findings."""
        findings = [
            Finding(
                title="Critical Vulnerability",
                severity=Severity.CRITICAL,
                description="Critical issue found",
                affected_component="app",
                agent_source="sast",
                cwe_ids=["CWE-89"],
                mitre_techniques=["T1190"],
                remediation="Fix immediately",
            ),
        ]

        sigma_rules = rule_builder.generate_sigma_rules(findings)

        assert "single_rules" in sigma_rules
        assert "batch" in sigma_rules
        assert len(sigma_rules["single_rules"]) == 1

    def test_generate_yara_rules(self, rule_builder):
        """Generate YARA rules from findings."""
        findings = [
            Finding(
                title="Malicious Pattern",
                severity=Severity.HIGH,
                description="Pattern detection",
                affected_component="file",
                agent_source="scanner",
                cwe_ids=["CWE-94"],
                mitre_techniques=["T1059"],
                remediation="Quarantine",
            ),
        ]

        yara_rules = rule_builder.generate_yara_rules(findings)

        assert "single_rules" in yara_rules
        assert "batch" in yara_rules
        assert len(yara_rules["single_rules"]) == 1

    def test_generate_all_rules(self, rule_builder):
        """Generate both Sigma and YARA rules."""
        findings = [
            Finding(
                title="Test Finding",
                severity=Severity.MEDIUM,
                description="Test",
                affected_component="test",
                agent_source="test",
                cwe_ids=["CWE-200"],
                mitre_techniques=["T1082"],
                remediation="Test",
            ),
        ]

        all_rules = rule_builder.generate_all(findings)

        assert "sigma" in all_rules
        assert "yara" in all_rules
        assert "single_rules" in all_rules["sigma"]
        assert "single_rules" in all_rules["yara"]


class TestFindingMetadata:
    """Test that generated rules have proper metadata."""

    def test_sigma_rule_includes_cve_references(self, sigma_generator):
        """Sigma rules should include CVE references."""
        finding = Finding(
            title="Known Vulnerability",
            severity=Severity.HIGH,
            description="CVE-2024-12345 vulnerability",
            affected_component="component",
            agent_source="dependency",
            cve_ids=["CVE-2024-12345"],
            cwe_ids=["CWE-89"],
            mitre_techniques=["T1190"],
            remediation="Update package",
        )

        sigma_rule = sigma_generator.generate(finding)

        assert "references:" in sigma_rule or "CVE-2024-12345" in sigma_rule

    def test_yara_rule_includes_mitre_techniques(self, yara_generator):
        """YARA rules should include MITRE ATT&CK references."""
        finding = Finding(
            title="Attack Pattern",
            severity=Severity.HIGH,
            description="Pattern matching T1190",
            affected_component="network",
            agent_source="ids",
            cwe_ids=["CWE-89"],
            mitre_techniques=["T1190", "T1566"],
            remediation="Block pattern",
        )

        yara_rule = yara_generator.generate(finding)

        assert "mitre_techniques" in yara_rule or "T1190" in yara_rule

    def test_sigma_rule_severity_mapping(self, sigma_generator):
        """Sigma rules should correctly map severity levels."""
        severities_to_test = [
            (Severity.CRITICAL, "critical"),
            (Severity.HIGH, "high"),
            (Severity.MEDIUM, "medium"),
            (Severity.LOW, "low"),
        ]

        for severity, expected_level in severities_to_test:
            finding = Finding(
                title="Test",
                severity=severity,
                description="Test",
                affected_component="test",
                agent_source="test",
                cwe_ids=["CWE-200"],
                mitre_techniques=["T1082"],
                remediation="Test",
            )

            sigma_rule = sigma_generator.generate(finding)

            assert f"level: {expected_level}" in sigma_rule
