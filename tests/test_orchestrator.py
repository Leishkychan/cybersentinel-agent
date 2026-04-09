"""Tests for the orchestrator."""

import pytest

from cybersentinel.core.orchestrator import Orchestrator, DISPATCH_TABLE
from cybersentinel.models.finding import Finding, Severity
from cybersentinel.models.session import Session, SessionMode


@pytest.fixture
def session():
    s = Session(mode=SessionMode.GUIDED)
    s.add_target("webapp.example.com", approved_by="test_operator")
    return s


@pytest.fixture
def orchestrator(session):
    return Orchestrator(session=session)


class TestScopeValidation:
    def test_valid_scope(self, orchestrator):
        assert orchestrator.validate_scope()

    def test_empty_scope_fails(self):
        session = Session(mode=SessionMode.GUIDED)
        orch = Orchestrator(session=session)
        with pytest.raises(ValueError, match="No targets in scope"):
            orch.validate_scope()


class TestClassification:
    def test_valid_target_type(self, orchestrator):
        agents = orchestrator.classify("source_code")
        assert "sast" in agents
        assert "dependency" in agents

    def test_invalid_target_type(self, orchestrator):
        with pytest.raises(ValueError, match="Unknown target type"):
            orchestrator.classify("invalid_type")

    def test_dispatch_table_has_expected_types(self):
        expected = ["full_scan", "source_code", "web_app", "infrastructure",
                     "network", "recon_only", "email_security"]
        for t in expected:
            assert t in DISPATCH_TABLE, f"Missing dispatch type: {t}"

    def test_all_dispatch_entries_are_lists(self):
        for target_type, agents in DISPATCH_TABLE.items():
            assert isinstance(agents, list), f"{target_type} dispatch is not a list"
            assert len(agents) > 0, f"{target_type} has empty agent list"


class TestCheckpoint:
    def test_checkpoint_blocks_report(self, orchestrator):
        with pytest.raises(PermissionError):
            orchestrator.generate_report()

    def test_checkpoint_format(self, orchestrator):
        finding = Finding(
            title="Test XSS",
            severity=Severity.HIGH,
            description="Reflected XSS in search",
            affected_component="/search",
            agent_source="sast",
        )
        orchestrator.add_finding(finding)
        checkpoint = orchestrator.checkpoint()
        assert "CHECKPOINT" in checkpoint
        assert "AWAITING HUMAN APPROVAL" in checkpoint
        assert "High: 1" in checkpoint

    def test_checkpoint_then_approve(self, orchestrator):
        finding = Finding(
            title="Test",
            severity=Severity.MEDIUM,
            description="Test finding",
            affected_component="/test",
            agent_source="config",
        )
        orchestrator.add_finding(finding)
        orchestrator.checkpoint()
        orchestrator.approve_checkpoint(approved_by="test_operator")
        report = orchestrator.generate_report()
        assert "Test" in report


class TestConflictResolution:
    def test_severity_mismatch_detected(self, orchestrator):
        f1 = Finding(
            title="Config Issue",
            severity=Severity.HIGH,
            description="From agent 1",
            affected_component="/etc/nginx.conf",
            agent_source="config",
        )
        f2 = Finding(
            title="Config Issue",
            severity=Severity.MEDIUM,
            description="From agent 2",
            affected_component="/etc/nginx.conf",
            agent_source="hardening",
        )
        orchestrator.add_finding(f1)
        orchestrator.add_finding(f2)
        conflicts = orchestrator.resolve_conflicts()
        assert len(conflicts) == 1
        assert conflicts[0]["type"] == "severity_mismatch"


class TestFindingImmutability:
    def test_findings_are_append_only(self, orchestrator):
        finding = Finding(
            title="Test",
            severity=Severity.LOW,
            description="Test",
            affected_component="/test",
            agent_source="test",
        )
        orchestrator.add_finding(finding)
        assert len(orchestrator.session.findings) == 1
        assert not hasattr(orchestrator, "delete_finding")
        assert not hasattr(orchestrator, "remove_finding")
