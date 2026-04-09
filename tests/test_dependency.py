"""Tests for the Dependency Agent — Software Composition Analysis.

Tests verify parsing of manifest files and matching against known vulnerabilities
across npm, Python, Maven, and Go ecosystems.
"""

import pytest

from cybersentinel.agents.dependency import DependencyAgent
from cybersentinel.models.finding import Severity
from cybersentinel.models.session import Session, SessionMode


@pytest.fixture
def session():
    """Create a test session with one approved target."""
    s = Session(mode=SessionMode.GUIDED)
    s.add_target("test-target", approved_by="test_operator")
    return s


@pytest.fixture
def dependency_agent(session):
    """Create a Dependency agent instance."""
    return DependencyAgent(session)


class TestRequirementsParsing:
    """Test parsing of Python requirements.txt files."""

    def test_parse_simple_requirements(self, dependency_agent, session):
        """Parse basic requirements.txt with version constraints."""
        manifest = """
flask==2.2.0
requests>=2.28.0
django~=4.0
numpy
pillow==9.4.0
        """
        findings = dependency_agent.analyze("test-target", {
            "manifest": manifest,
            "manifest_type": "requirements.txt"
        })

        # flask==2.2.0 should trigger CVE-2023-30861
        assert len(findings) > 0
        flask_vuln = next((f for f in findings if "flask" in f.affected_component.lower()), None)
        assert flask_vuln is not None
        assert "CVE-2023-30861" in flask_vuln.cve_ids
        assert flask_vuln.severity == Severity.HIGH

    def test_flask_vulnerable_version(self, dependency_agent, session):
        """Flask 2.2.0 should flag CVE-2023-30861."""
        manifest = "flask==2.2.0\n"
        findings = dependency_agent.analyze("test-target", {
            "manifest": manifest,
            "manifest_type": "requirements.txt"
        })

        assert len(findings) > 0
        assert any("CVE-2023-30861" in f.cve_ids for f in findings)
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_flask_patched_version(self, dependency_agent, session):
        """Flask 2.3.2 should not flag any CVE-2023-30861."""
        manifest = "flask==2.3.2\n"
        findings = dependency_agent.analyze("test-target", {
            "manifest": manifest,
            "manifest_type": "requirements.txt"
        })

        # Should not find the CVE-2023-30861 vulnerability
        assert not any("CVE-2023-30861" in f.cve_ids for f in findings)

    def test_django_vulnerability(self, dependency_agent, session):
        """Django 4.2.0 should flag CVE-2023-46695."""
        manifest = "django==4.2.0\n"
        findings = dependency_agent.analyze("test-target", {
            "manifest": manifest,
            "manifest_type": "requirements.txt"
        })

        assert len(findings) > 0
        assert any("django" in f.affected_component.lower() for f in findings)
        assert any("CVE-2023-46695" in f.cve_ids for f in findings)

    def test_pyyaml_critical_vulnerability(self, dependency_agent, session):
        """PyYAML < 5.4 should flag critical CVE-2020-14343."""
        manifest = "pyyaml==5.3\n"
        findings = dependency_agent.analyze("test-target", {
            "manifest": manifest,
            "manifest_type": "requirements.txt"
        })

        assert len(findings) > 0
        pyyaml_vuln = next((f for f in findings if "pyyaml" in f.affected_component.lower()), None)
        assert pyyaml_vuln is not None
        assert "CVE-2020-14343" in pyyaml_vuln.cve_ids
        assert pyyaml_vuln.severity == Severity.CRITICAL

    def test_requirements_with_comments(self, dependency_agent, session):
        """Parse requirements.txt with comments and blank lines."""
        manifest = """
# Core dependencies
flask==2.2.0
# Async support
requests>=2.28.0

# Database
django==4.2.0
        """
        findings = dependency_agent.analyze("test-target", {
            "manifest": manifest,
            "manifest_type": "requirements.txt"
        })

        assert len(findings) > 0

    def test_requirements_with_pip_flags(self, dependency_agent, session):
        """Parse requirements.txt with pip flags."""
        manifest = """
--index-url https://pypi.org/simple/
flask==2.2.0
-e git+https://github.com/pallets/flask.git#egg=flask
pillow==9.4.0
        """
        findings = dependency_agent.analyze("test-target", {
            "manifest": manifest,
            "manifest_type": "requirements.txt"
        })

        assert len(findings) > 0


class TestPackageJsonParsing:
    """Test parsing of npm package.json files."""

    def test_parse_package_json_dependencies(self, dependency_agent, session):
        """Parse package.json with dependencies."""
        manifest = """{
  "name": "test-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "4.18.0",
    "lodash": "4.17.19",
    "axios": "1.5.0"
  }
}"""
        findings = dependency_agent.analyze("test-target", {
            "manifest": manifest,
            "manifest_type": "package.json"
        })

        assert len(findings) > 0
        # lodash 4.17.19 should flag CVE-2021-23337
        lodash_vuln = next((f for f in findings if "lodash" in f.affected_component.lower()), None)
        assert lodash_vuln is not None
        assert "CVE-2021-23337" in lodash_vuln.cve_ids

    def test_lodash_vulnerable_version(self, dependency_agent, session):
        """Lodash 4.17.19 should flag multiple CVEs."""
        manifest = """{
  "dependencies": {
    "lodash": "4.17.19"
  }
}"""
        findings = dependency_agent.analyze("test-target", {
            "manifest": manifest,
            "manifest_type": "package.json"
        })

        assert len(findings) > 0
        cves = set()
        for f in findings:
            if "lodash" in f.affected_component.lower():
                cves.update(f.cve_ids)
        assert len(cves) > 0

    def test_lodash_patched_version(self, dependency_agent, session):
        """Lodash 4.17.21 should not flag CVE-2021-23337."""
        manifest = """{
  "dependencies": {
    "lodash": "4.17.21"
  }
}"""
        findings = dependency_agent.analyze("test-target", {
            "manifest": manifest,
            "manifest_type": "package.json"
        })

        # Should not find the vulnerability
        assert not any("CVE-2021-23337" in f.cve_ids for f in findings)

    def test_package_json_with_caret_version(self, dependency_agent, session):
        """Parse npm version specifiers (^, ~, >=)."""
        manifest = """{
  "dependencies": {
    "express": "^4.18.0",
    "lodash": "~4.17.19",
    "axios": ">=1.5.0"
  }
}"""
        findings = dependency_agent.analyze("test-target", {
            "manifest": manifest,
            "manifest_type": "package.json"
        })

        assert len(findings) > 0

    def test_package_json_dev_dependencies(self, dependency_agent, session):
        """Parse devDependencies and peerDependencies."""
        manifest = """{
  "dependencies": {
    "express": "4.19.0"
  },
  "devDependencies": {
    "jest": "29.0.0",
    "lodash": "4.17.19"
  }
}"""
        findings = dependency_agent.analyze("test-target", {
            "manifest": manifest,
            "manifest_type": "package.json"
        })

        assert len(findings) > 0
        # Should find lodash vulnerability in dev dependencies
        assert any("lodash" in f.affected_component.lower() for f in findings)

    def test_jsonwebtoken_vulnerability(self, dependency_agent, session):
        """jsonwebtoken < 9.0.0 should flag CVE-2022-23529."""
        manifest = """{
  "dependencies": {
    "jsonwebtoken": "8.5.1"
  }
}"""
        findings = dependency_agent.analyze("test-target", {
            "manifest": manifest,
            "manifest_type": "package.json"
        })

        assert len(findings) > 0
        assert any("CVE-2022-23529" in f.cve_ids for f in findings)


class TestGoModParsing:
    """Test parsing of Go go.mod files."""

    def test_parse_go_mod_basic(self, dependency_agent, session):
        """Parse go.mod with require blocks."""
        manifest = """module example.com/myapp

go 1.20

require (
    golang.org/x/net v0.15.0
    golang.org/x/text v0.13.0
)
        """
        findings = dependency_agent.analyze("test-target", {
            "manifest": manifest,
            "manifest_type": "go.mod"
        })

        # golang.org/x/net v0.15.0 should flag CVE-2023-44487
        assert len(findings) > 0
        net_vuln = next((f for f in findings if "golang.org/x/net" in f.affected_component), None)
        assert net_vuln is not None
        assert "CVE-2023-44487" in net_vuln.cve_ids
        assert net_vuln.cisa_kev

    def test_golang_net_vulnerable_version(self, dependency_agent, session):
        """golang.org/x/net < 0.17.0 should flag CVE-2023-44487."""
        manifest = """module example.com/test

require golang.org/x/net v0.16.0
        """
        findings = dependency_agent.analyze("test-target", {
            "manifest": manifest,
            "manifest_type": "go.mod"
        })

        assert len(findings) > 0
        assert any("CVE-2023-44487" in f.cve_ids for f in findings)
        assert any(f.cisa_kev for f in findings)

    def test_golang_net_patched_version(self, dependency_agent, session):
        """golang.org/x/net v0.17.0 should not flag CVE-2023-44487."""
        manifest = """module example.com/test

require golang.org/x/net v0.17.0
        """
        findings = dependency_agent.analyze("test-target", {
            "manifest": manifest,
            "manifest_type": "go.mod"
        })

        # Should not find the vulnerability
        assert not any("CVE-2023-44487" in f.cve_ids for f in findings)

    def test_golang_text_vulnerability(self, dependency_agent, session):
        """golang.org/x/text < 0.3.8 should flag CVE-2022-32149."""
        manifest = """module example.com/test

require golang.org/x/text v0.3.5
        """
        findings = dependency_agent.analyze("test-target", {
            "manifest": manifest,
            "manifest_type": "go.mod"
        })

        assert len(findings) > 0
        assert any("CVE-2022-32149" in f.cve_ids for f in findings)

    def test_go_mod_inline_require(self, dependency_agent, session):
        """Parse inline require statements."""
        manifest = """module example.com/test

go 1.20

require golang.org/x/net v0.15.0
require golang.org/x/text v0.3.5
        """
        findings = dependency_agent.analyze("test-target", {
            "manifest": manifest,
            "manifest_type": "go.mod"
        })

        assert len(findings) > 0


class TestPomXmlParsing:
    """Test parsing of Maven pom.xml files."""

    def test_parse_pom_xml_basic(self, dependency_agent, session):
        """Parse pom.xml with dependencies."""
        manifest = """<?xml version="1.0" encoding="UTF-8"?>
<project>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.1</version>
    </dependency>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-framework</artifactId>
      <version>5.3.0</version>
    </dependency>
  </dependencies>
</project>"""
        findings = dependency_agent.analyze("test-target", {
            "manifest": manifest,
            "manifest_type": "pom.xml"
        })

        assert len(findings) > 0
        # log4j-core 2.14.1 should flag Log4Shell CVE-2021-44228
        log4j_vuln = next(
            (f for f in findings if "log4j-core" in f.affected_component),
            None
        )
        assert log4j_vuln is not None
        assert "CVE-2021-44228" in log4j_vuln.cve_ids
        assert log4j_vuln.severity == Severity.CRITICAL

    def test_log4j_critical_vulnerability(self, dependency_agent, session):
        """log4j-core < 2.17.0 should flag critical Log4Shell."""
        manifest = """<project>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.16.0</version>
    </dependency>
  </dependencies>
</project>"""
        findings = dependency_agent.analyze("test-target", {
            "manifest": manifest,
            "manifest_type": "pom.xml"
        })

        assert len(findings) > 0
        log4j_vuln = next((f for f in findings if "log4j" in f.affected_component), None)
        assert log4j_vuln is not None
        assert log4j_vuln.severity == Severity.CRITICAL
        assert log4j_vuln.cisa_kev

    def test_log4j_patched_version(self, dependency_agent, session):
        """log4j-core 2.17.0 should not flag Log4Shell."""
        manifest = """<project>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.17.0</version>
    </dependency>
  </dependencies>
</project>"""
        findings = dependency_agent.analyze("test-target", {
            "manifest": manifest,
            "manifest_type": "pom.xml"
        })

        # Should not find Log4Shell CVE
        assert not any("CVE-2021-44228" in f.cve_ids for f in findings)

    def test_spring_vulnerability(self, dependency_agent, session):
        """Spring Framework < 5.3.18 should flag Spring4Shell."""
        manifest = """<project>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-framework</artifactId>
      <version>5.3.0</version>
    </dependency>
  </dependencies>
</project>"""
        findings = dependency_agent.analyze("test-target", {
            "manifest": manifest,
            "manifest_type": "pom.xml"
        })

        assert len(findings) > 0
        spring_vuln = next(
            (f for f in findings if "spring-framework" in f.affected_component),
            None
        )
        assert spring_vuln is not None
        assert "CVE-2022-22965" in spring_vuln.cve_ids
        assert spring_vuln.severity == Severity.CRITICAL
        assert spring_vuln.cisa_kev

    def test_jackson_databind_vulnerability(self, dependency_agent, session):
        """jackson-databind with vulnerable version should be flagged."""
        manifest = """<project>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.databind</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.13.0</version>
    </dependency>
  </dependencies>
</project>"""
        findings = dependency_agent.analyze("test-target", {
            "manifest": manifest,
            "manifest_type": "pom.xml"
        })

        assert len(findings) > 0
        jackson_vuln = next(
            (f for f in findings if "jackson-databind" in f.affected_component),
            None
        )
        assert jackson_vuln is not None
        assert "CVE-2020-36518" in jackson_vuln.cve_ids


class TestAutoDetection:
    """Test auto-detection of manifest type."""

    def test_auto_detect_package_json(self, dependency_agent, session):
        """Auto-detect npm package.json format."""
        manifest = '{"dependencies": {"lodash": "4.17.19"}}'
        findings = dependency_agent.analyze("test-target", {
            "manifest": manifest,
            "manifest_type": ""  # Empty, should auto-detect
        })

        assert len(findings) > 0
        assert any("lodash" in f.affected_component.lower() for f in findings)

    def test_auto_detect_go_mod(self, dependency_agent, session):
        """Auto-detect go.mod format."""
        manifest = "module example.com/test\nrequire golang.org/x/net v0.15.0"
        findings = dependency_agent.analyze("test-target", {
            "manifest": manifest,
            "manifest_type": ""  # Empty, should auto-detect
        })

        assert len(findings) > 0

    def test_auto_detect_pom_xml(self, dependency_agent, session):
        """Auto-detect pom.xml format."""
        manifest = """<project>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.1</version>
    </dependency>
  </dependencies>
</project>"""
        findings = dependency_agent.analyze("test-target", {
            "manifest": manifest,
            "manifest_type": ""  # Empty, should auto-detect
        })

        assert len(findings) > 0


class TestUnknownVersionHandling:
    """Test handling of unknown or missing versions."""

    def test_unknown_version_low_confidence(self, dependency_agent, session):
        """Dependencies with unknown version should have low confidence."""
        manifest = """
flask
requests
django
        """
        findings = dependency_agent.analyze("test-target", {
            "manifest": manifest,
            "manifest_type": "requirements.txt"
        })

        # Findings with unknown version should have low confidence
        for finding in findings:
            if "version" in finding.description.lower() and "unknown" in finding.description.lower():
                assert finding.confidence == "low"

    def test_empty_manifest_no_findings(self, dependency_agent, session):
        """Empty manifest should produce no findings."""
        findings = dependency_agent.analyze("test-target", {
            "manifest": "",
            "manifest_type": "requirements.txt"
        })

        assert len(findings) == 0

    def test_whitespace_only_manifest(self, dependency_agent, session):
        """Whitespace-only manifest should produce no findings."""
        findings = dependency_agent.analyze("test-target", {
            "manifest": "\n\n  \n  \n",
            "manifest_type": "requirements.txt"
        })

        assert len(findings) == 0


class TestFindingMetadata:
    """Test that dependency findings have correct metadata."""

    def test_finding_has_cve_ids(self, dependency_agent, session):
        """All findings must have CVE IDs."""
        manifest = "flask==2.2.0\n"
        findings = dependency_agent.analyze("test-target", {
            "manifest": manifest,
            "manifest_type": "requirements.txt"
        })

        for finding in findings:
            assert len(finding.cve_ids) > 0
            assert all(cve.startswith("CVE-") for cve in finding.cve_ids)

    def test_finding_has_cwe_ids(self, dependency_agent, session):
        """All findings must have CWE IDs."""
        manifest = "flask==2.2.0\n"
        findings = dependency_agent.analyze("test-target", {
            "manifest": manifest,
            "manifest_type": "requirements.txt"
        })

        for finding in findings:
            assert len(finding.cwe_ids) > 0
            assert all(cwe.startswith("CWE-") for cwe in finding.cwe_ids)

    def test_finding_has_remediation(self, dependency_agent, session):
        """All findings must have remediation steps."""
        manifest = "pyyaml==5.3\n"
        findings = dependency_agent.analyze("test-target", {
            "manifest": manifest,
            "manifest_type": "requirements.txt"
        })

        for finding in findings:
            assert finding.remediation
            assert "update" in finding.remediation.lower()

    def test_finding_has_severity(self, dependency_agent, session):
        """All findings must have severity level."""
        manifest = "flask==2.2.0\ndjango==4.2.0\n"
        findings = dependency_agent.analyze("test-target", {
            "manifest": manifest,
            "manifest_type": "requirements.txt"
        })

        for finding in findings:
            assert finding.severity in [
                Severity.CRITICAL,
                Severity.HIGH,
                Severity.MEDIUM,
                Severity.LOW,
                Severity.INFO,
            ]

    def test_finding_has_cvss_score(self, dependency_agent, session):
        """Dependency findings should have CVSS scores."""
        manifest = "flask==2.2.0\n"
        findings = dependency_agent.analyze("test-target", {
            "manifest": manifest,
            "manifest_type": "requirements.txt"
        })

        for finding in findings:
            assert hasattr(finding, 'cvss_score')
            assert 0.0 <= finding.cvss_score <= 10.0

    def test_critical_vulnerabilities_marked_kev(self, dependency_agent, session):
        """Critical, exploited vulnerabilities should be marked as CISA KEV."""
        manifest = """<?xml version="1.0"?>
<project>
    <dependencies>
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-core</artifactId>
            <version>2.14.0</version>
        </dependency>
    </dependencies>
</project>"""
        findings = dependency_agent.analyze("test-target", {
            "manifest": manifest,
            "manifest_type": "pom.xml"
        })

        kev_findings = [f for f in findings if f.cisa_kev]
        assert len(kev_findings) > 0, "Log4Shell should be marked as CISA KEV"
