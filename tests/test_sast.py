"""Tests for the SAST Agent — Static Application Security Testing.

Tests verify detection of common vulnerability patterns across multiple
languages with correct severity, CWE, and MITRE ATT&CK mappings.
"""

import pytest

from cybersentinel.agents.sast import SASTAgent
from cybersentinel.models.finding import Severity
from cybersentinel.models.session import Session, SessionMode


@pytest.fixture
def session():
    """Create a test session with one approved target."""
    s = Session(mode=SessionMode.GUIDED)
    s.add_target("test-target", approved_by="test_operator")
    return s


@pytest.fixture
def sast_agent(session):
    """Create a SAST agent instance."""
    return SASTAgent(session)


class TestSQLInjectionDetection:
    """Test SQL injection detection patterns."""

    def test_sql_injection_string_concatenation(self, sast_agent, session):
        """Detect SQL injection via string concatenation."""
        code = """
query = "SELECT * FROM users WHERE id = " + user_id
cursor.execute(query)
        """
        findings = sast_agent.analyze("test-target", {
            "code": code,
            "language": "python",
            "filename": "test.py"
        })

        assert len(findings) > 0
        finding = findings[0]
        assert "SQL Injection" in finding.title
        assert finding.severity == Severity.CRITICAL
        assert "CWE-89" in finding.cwe_ids
        assert "T1190" in finding.mitre_techniques

    def test_sql_injection_format_string(self, sast_agent, session):
        """Detect SQL injection via string formatting."""
        code = """
db.execute(f"SELECT * FROM users WHERE username = '{user_input}'")
        """
        findings = sast_agent.analyze("test-target", {
            "code": code,
            "language": "python",
            "filename": "app.py"
        })

        assert len(findings) > 0
        assert any("SQL" in f.title for f in findings)

    def test_sql_injection_variable_interpolation(self, sast_agent, session):
        """Detect SQL injection via variable interpolation in query."""
        code = """
query = "INSERT INTO users VALUES (" + name + ", " + email + ")"
        """
        findings = sast_agent.analyze("test-target", {
            "code": code,
            "language": "python",
            "filename": "insert.py"
        })

        assert len(findings) > 0
        assert any("SQL" in f.title for f in findings)

    def test_sql_injection_javascript(self, sast_agent, session):
        """Detect SQL injection in JavaScript."""
        code = """
const query = "SELECT * FROM users WHERE id = " + userId;
sequelize.query(query);
        """
        findings = sast_agent.analyze("test-target", {
            "code": code,
            "language": "javascript",
            "filename": "app.js"
        })

        assert len(findings) > 0
        assert any("SQL" in f.title for f in findings)

    def test_clean_sql_no_findings(self, sast_agent, session):
        """Parameterized queries should not trigger findings."""
        code = """
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, [user_id])
        """
        findings = sast_agent.analyze("test-target", {
            "code": code,
            "language": "python",
            "filename": "safe.py"
        })

        # Should not find SQL injection
        assert not any("SQL" in f.title for f in findings)


class TestCommandInjectionDetection:
    """Test command injection detection patterns."""

    def test_command_injection_os_system(self, sast_agent, session):
        """Detect command injection via os.system()."""
        code = """
import os
os.system("ping " + hostname)
        """
        findings = sast_agent.analyze("test-target", {
            "code": code,
            "language": "python",
            "filename": "cmd.py"
        })

        assert len(findings) > 0
        finding = next((f for f in findings if "Command Injection" in f.title), None)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL
        assert "CWE-78" in finding.cwe_ids
        assert "T1059" in finding.mitre_techniques

    def test_command_injection_subprocess_shell_true(self, sast_agent, session):
        """Detect command injection via subprocess with shell=True."""
        code = """
import subprocess
subprocess.call("ls " + directory, shell=True)
        """
        findings = sast_agent.analyze("test-target", {
            "code": code,
            "language": "python",
            "filename": "process.py"
        })

        assert len(findings) > 0
        assert any("shell=True" in f.title for f in findings)
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_command_injection_javascript(self, sast_agent, session):
        """Detect command injection in JavaScript."""
        code = """
const exec = require('child_process').exec;
exec("echo " + userInput);
        """
        findings = sast_agent.analyze("test-target", {
            "code": code,
            "language": "javascript",
            "filename": "exec.js"
        })

        assert len(findings) > 0
        assert any("Command Injection" in f.title for f in findings)

    def test_command_injection_java(self, sast_agent, session):
        """Detect command injection in Java."""
        code = """
Runtime.getRuntime().exec("cat " + filename);
        """
        findings = sast_agent.analyze("test-target", {
            "code": code,
            "language": "java",
            "filename": "exec.java"
        })

        assert len(findings) > 0
        assert any("Command Injection" in f.title for f in findings)

    def test_clean_subprocess_no_injection(self, sast_agent, session):
        """subprocess.call with list and shell=False should not trigger findings."""
        code = """
import subprocess
subprocess.call(["ls", "-la", directory], shell=False)
        """
        findings = sast_agent.analyze("test-target", {
            "code": code,
            "language": "python",
            "filename": "safe_proc.py"
        })

        # Should not find command injection
        assert not any("shell=True" in f.title for f in findings)


class TestXSSDetection:
    """Test Cross-Site Scripting (XSS) detection patterns."""

    def test_xss_innerHTML(self, sast_agent, session):
        """Detect XSS via innerHTML assignment."""
        code = """
document.getElementById('output').innerHTML = userInput;
        """
        findings = sast_agent.analyze("test-target", {
            "code": code,
            "language": "javascript",
            "filename": "xss.js"
        })

        assert len(findings) > 0
        finding = next((f for f in findings if "Cross-Site Scripting" in f.title or "XSS" in f.title), None)
        assert finding is not None
        assert finding.severity == Severity.HIGH
        assert "CWE-79" in finding.cwe_ids
        assert "T1189" in finding.mitre_techniques

    def test_xss_dangerouslySetInnerHTML(self, sast_agent, session):
        """Detect XSS via React's dangerouslySetInnerHTML."""
        code = """
<div dangerouslySetInnerHTML={{__html: userContent}} />
        """
        findings = sast_agent.analyze("test-target", {
            "code": code,
            "language": "javascript",
            "filename": "react.jsx"
        })

        assert len(findings) > 0
        assert any("Cross-Site Scripting" in f.title or "XSS" in f.title for f in findings)

    def test_xss_document_write(self, sast_agent, session):
        """Detect XSS via document.write()."""
        code = """
document.write(userInput);
        """
        findings = sast_agent.analyze("test-target", {
            "code": code,
            "language": "javascript",
            "filename": "doc.js"
        })

        assert len(findings) > 0
        assert any("Cross-Site Scripting" in f.title or "XSS" in f.title for f in findings)

    def test_xss_jinja_unescaped(self, sast_agent, session):
        """Detect XSS via Jinja2 unsafe filter."""
        code = """
{{ user_data|safe }}
{{ user_input|raw }}
        """
        findings = sast_agent.analyze("test-target", {
            "code": code,
            "language": "python",
            "filename": "template.html"
        })

        assert len(findings) > 0
        assert any("Cross-Site Scripting" in f.title or "XSS" in f.title for f in findings)

    def test_clean_xss_escaped(self, sast_agent, session):
        """HTML escaping should not trigger XSS findings."""
        code = """
document.getElementById('output').textContent = userInput;
{{ user_data|escape }}
        """
        findings = sast_agent.analyze("test-target", {
            "code": code,
            "language": "javascript",
            "filename": "safe_xss.js"
        })

        # Should not find XSS issues
        assert not any("Cross-Site Scripting" in f.title or "XSS" in f.title for f in findings)


class TestHardcodedSecretsDetection:
    """Test hardcoded secrets detection patterns."""

    def test_hardcoded_api_key(self, sast_agent, session):
        """Detect hardcoded API key."""
        code = """
api_key = "sk-1234567890abcdefgh"
headers = {"Authorization": "Bearer " + api_key}
        """
        findings = sast_agent.analyze("test-target", {
            "code": code,
            "language": "python",
            "filename": "config.py"
        })

        assert len(findings) > 0
        finding = next((f for f in findings if "Hardcoded Secret" in f.title), None)
        assert finding is not None
        assert finding.severity == Severity.HIGH
        assert "CWE-798" in finding.cwe_ids
        assert "T1552.001" in finding.mitre_techniques

    def test_hardcoded_aws_key(self, sast_agent, session):
        """Detect hardcoded AWS access key."""
        code = """
aws_access_key = "AKIAIOSFODNN7EXAMPLE"
aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        """
        findings = sast_agent.analyze("test-target", {
            "code": code,
            "language": "python",
            "filename": "aws.py"
        })

        assert len(findings) > 0
        finding = next((f for f in findings if "AWS" in f.title), None)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL

    def test_hardcoded_database_password(self, sast_agent, session):
        """Detect hardcoded database password."""
        code = """
DATABASE_PASSWORD = "MySecretPassword123!"
connection = connect(host="db.example.com", password=DATABASE_PASSWORD)
        """
        findings = sast_agent.analyze("test-target", {
            "code": code,
            "language": "python",
            "filename": "db.py"
        })

        assert len(findings) > 0
        assert any("Hardcoded Secret" in f.title for f in findings)

    def test_clean_secrets_no_findings(self, sast_agent, session):
        """Using environment variables should not trigger findings."""
        code = """
import os
api_key = os.getenv("API_KEY")
db_password = os.getenv("DB_PASSWORD")
        """
        findings = sast_agent.analyze("test-target", {
            "code": code,
            "language": "python",
            "filename": "safe_secrets.py"
        })

        # Should not find hardcoded secrets
        assert not any("Hardcoded Secret" in f.title for f in findings)


class TestWeakCryptoDetection:
    """Test weak cryptography detection patterns."""

    def test_weak_crypto_md5(self, sast_agent, session):
        """Detect usage of MD5 hashing."""
        code = """
import hashlib
hash = hashlib.md5(password.encode()).hexdigest()
        """
        findings = sast_agent.analyze("test-target", {
            "code": code,
            "language": "python",
            "filename": "hash.py"
        })

        assert len(findings) > 0
        finding = next((f for f in findings if "MD5" in f.title or "SHA1" in f.title), None)
        assert finding is not None
        assert finding.severity == Severity.MEDIUM
        assert "CWE-327" in finding.cwe_ids
        assert "T1600" in finding.mitre_techniques

    def test_weak_crypto_sha1(self, sast_agent, session):
        """Detect usage of SHA1 hashing."""
        code = """
hash = hashlib.sha1(password).hexdigest()
        """
        findings = sast_agent.analyze("test-target", {
            "code": code,
            "language": "python",
            "filename": "weak.py"
        })

        assert len(findings) > 0
        assert any("MD5" in f.title or "SHA1" in f.title for f in findings)

    def test_weak_crypto_ecb_mode(self, sast_agent, session):
        """Detect usage of ECB mode encryption."""
        code = """
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_ECB)
        """
        findings = sast_agent.analyze("test-target", {
            "code": code,
            "language": "python",
            "filename": "ecb.py"
        })

        assert len(findings) > 0
        assert any("ECB" in f.title or "weak cipher" in f.description.lower() for f in findings)

    def test_weak_crypto_des(self, sast_agent, session):
        """Detect usage of DES encryption."""
        code = """
cipher = DES.new(key, DES.MODE_CBC, iv)
        """
        findings = sast_agent.analyze("test-target", {
            "code": code,
            "language": "python",
            "filename": "des.py"
        })

        assert len(findings) > 0
        assert any("DES" in f.title or "weak" in f.title.lower() for f in findings)

    def test_clean_crypto_sha256(self, sast_agent, session):
        """SHA-256 usage should not trigger crypto findings."""
        code = """
import hashlib
hash = hashlib.sha256(password.encode()).hexdigest()
        """
        findings = sast_agent.analyze("test-target", {
            "code": code,
            "language": "python",
            "filename": "safe_hash.py"
        })

        # Should not find weak crypto
        assert not any("MD5" in f.title or "SHA1" in f.title for f in findings)


class TestMultiLanguageSupport:
    """Test SAST rules work across multiple languages."""

    def test_sql_injection_python(self, sast_agent, session):
        """SQL injection detection in Python."""
        code = "query = 'SELECT * FROM users WHERE id=' + id"
        findings = sast_agent.analyze("test-target", {
            "code": code,
            "language": "python",
            "filename": "test.py"
        })
        assert any("SQL" in f.title for f in findings)

    def test_sql_injection_javascript(self, sast_agent, session):
        """SQL injection detection in JavaScript."""
        code = "const query = 'SELECT * FROM users WHERE id=' + userId;"
        findings = sast_agent.analyze("test-target", {
            "code": code,
            "language": "javascript",
            "filename": "test.js"
        })
        assert any("SQL" in f.title for f in findings)

    def test_sql_injection_java(self, sast_agent, session):
        """SQL injection detection in Java."""
        code = 'String query = "SELECT * FROM users WHERE id=" + id;'
        findings = sast_agent.analyze("test-target", {
            "code": code,
            "language": "java",
            "filename": "Test.java"
        })
        assert any("SQL" in f.title for f in findings)

    def test_xss_python(self, sast_agent, session):
        """XSS detection in Python templates."""
        code = "{{ content|safe }}"
        findings = sast_agent.analyze("test-target", {
            "code": code,
            "language": "python",
            "filename": "template.html"
        })
        assert any("Cross-Site Scripting" in f.title or "XSS" in f.title for f in findings)

    def test_command_injection_python(self, sast_agent, session):
        """Command injection detection in Python."""
        code = "os.system('ping ' + host)"
        findings = sast_agent.analyze("test-target", {
            "code": code,
            "language": "python",
            "filename": "ping.py"
        })
        assert any("Command" in f.title for f in findings)

    def test_command_injection_javascript(self, sast_agent, session):
        """Command injection detection in JavaScript."""
        code = "exec('ls ' + directory)"
        findings = sast_agent.analyze("test-target", {
            "code": code,
            "language": "javascript",
            "filename": "ls.js"
        })
        assert any("Command" in f.title for f in findings)


class TestFindingMetadata:
    """Test that findings have correct metadata and mappings."""

    def test_finding_has_severity(self, sast_agent, session):
        """All findings must have severity."""
        code = "SELECT * FROM users WHERE id = ' + id"
        findings = sast_agent.analyze("test-target", {
            "code": code,
            "language": "python",
            "filename": "test.py"
        })

        for finding in findings:
            assert finding.severity in [
                Severity.CRITICAL,
                Severity.HIGH,
                Severity.MEDIUM,
                Severity.LOW,
                Severity.INFO,
            ]

    def test_finding_has_cwe(self, sast_agent, session):
        """All findings must have CWE IDs."""
        code = "os.system('ping ' + host)"
        findings = sast_agent.analyze("test-target", {
            "code": code,
            "language": "python",
            "filename": "test.py"
        })

        for finding in findings:
            assert len(finding.cwe_ids) > 0
            assert all(cwe.startswith("CWE-") for cwe in finding.cwe_ids)

    def test_finding_has_mitre_techniques(self, sast_agent, session):
        """All findings must have MITRE ATT&CK techniques."""
        code = "api_key = 'secret123456789'"
        findings = sast_agent.analyze("test-target", {
            "code": code,
            "language": "python",
            "filename": "test.py"
        })

        for finding in findings:
            assert len(finding.mitre_techniques) > 0
            assert all(t.startswith("T") for t in finding.mitre_techniques)

    def test_finding_has_remediation(self, sast_agent, session):
        """All findings must have remediation guidance."""
        code = "query = 'SELECT * FROM users WHERE id=' + id"
        findings = sast_agent.analyze("test-target", {
            "code": code,
            "language": "python",
            "filename": "test.py"
        })

        for finding in findings:
            assert finding.remediation
            assert len(finding.remediation) > 0

    def test_finding_has_affected_component(self, sast_agent, session):
        """Findings must identify affected file/component."""
        code = "os.system(cmd)"
        findings = sast_agent.analyze("test-target", {
            "code": code,
            "language": "python",
            "filename": "app.py"
        })

        for finding in findings:
            assert finding.affected_component
            assert "app.py" in finding.affected_component


class TestEmptyAndCleanCode:
    """Test handling of empty and clean code."""

    def test_empty_code_no_findings(self, sast_agent, session):
        """Empty code should produce no findings."""
        findings = sast_agent.analyze("test-target", {
            "code": "",
            "language": "python",
            "filename": "empty.py"
        })
        assert len(findings) == 0

    def test_comments_only_no_findings(self, sast_agent, session):
        """Comments only should produce no findings."""
        code = """
# This is a comment
# Another comment
# TODO: implement feature
        """
        findings = sast_agent.analyze("test-target", {
            "code": code,
            "language": "python",
            "filename": "comments.py"
        })
        assert len(findings) == 0

    def test_clean_code_no_findings(self, sast_agent, session):
        """Clean, secure code should produce no findings."""
        code = """
import hashlib
from passlib.context import CryptContext

crypt = CryptContext(schemes=["bcrypt"])

def hash_password(password: str) -> str:
    return crypt.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return crypt.verify(password, hashed)

database_url = os.getenv("DATABASE_URL")
api_key = os.getenv("API_KEY")
        """
        findings = sast_agent.analyze("test-target", {
            "code": code,
            "language": "python",
            "filename": "secure.py"
        })

        # Should have no critical/high/medium findings
        critical_findings = [f for f in findings if f.severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]]
        assert len(critical_findings) == 0
