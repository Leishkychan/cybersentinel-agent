"""Tests for the safety enforcement layer.

These tests verify that all 5 safety rules are enforced as hard gates.
If any of these tests fail, the framework is NOT safe to use.
"""

import pytest

from cybersentinel.core.safety import (
    HardStop,
    ModeViolation,
    ScopeViolation,
    CredentialViolation,
    NetworkViolation,
    contains_credentials,
    validate_action,
    validate_text_output,
)
from cybersentinel.models.action import Action, ActionType
from cybersentinel.models.session import Session, SessionMode


@pytest.fixture
def session():
    """Create a test session with one approved target."""
    s = Session(mode=SessionMode.GUIDED)
    s.add_target("192.168.1.0/24", approved_by="test_operator")
    return s


# --- Rule 0: Scope Validation ---

class TestScopeValidation:
    def test_approved_target_passes(self, session):
        action = Action(
            type=ActionType.ANALYZE,
            agent_name="test",
            target="192.168.1.0/24",
            description="Test analysis",
        )
        assert validate_action("test", action, "192.168.1.0/24", session)

    def test_unapproved_target_blocked(self, session):
        action = Action(
            type=ActionType.ANALYZE,
            agent_name="test",
            target="10.0.0.1",
            description="Out of scope analysis",
        )
        with pytest.raises(ScopeViolation):
            validate_action("test", action, "10.0.0.1", session)

    def test_scope_violation_logged(self, session):
        action = Action(
            type=ActionType.ANALYZE,
            agent_name="test",
            target="10.0.0.1",
            description="Out of scope",
        )
        with pytest.raises(ScopeViolation):
            validate_action("test", action, "10.0.0.1", session)
        violations = [
            e for e in session.audit_log
            if e["event_type"] == "scope_violation"
        ]
        assert len(violations) == 1


# --- Rule 1: No Execution Without Human Approval ---

class TestModeEnforcement:
    def test_passive_mode_allows_scanning(self):
        """New rule: scanning is unrestricted in ALL modes."""
        session = Session(mode=SessionMode.PASSIVE)
        session.add_target("target", approved_by="test")
        action = Action(
            type=ActionType.GENERATE_COMMANDS,
            agent_name="test",
            target="target",
            description="Generate nmap command",
        )
        # Scanning is now unrestricted — should NOT raise
        assert validate_action("test", action, "target", session)

    def test_guided_mode_allows_commands(self, session):
        action = Action(
            type=ActionType.GENERATE_COMMANDS,
            agent_name="test",
            target="192.168.1.0/24",
            description="Generate scan command",
        )
        assert validate_action("test", action, "192.168.1.0/24", session)

    def test_destructive_always_blocked(self, session):
        action = Action(
            type=ActionType.EXECUTE_WITH_APPROVAL,
            agent_name="test",
            target="192.168.1.0/24",
            description="rm -rf /",
            is_destructive=True,
        )
        # Even in ACTIVE mode, destructive is blocked
        session.mode = SessionMode.ACTIVE
        with pytest.raises(HardStop):
            validate_action("test", action, "192.168.1.0/24", session)


# --- Rule 2: No Credentials ---

class TestCredentialProtection:
    def test_credential_action_blocked(self, session):
        action = Action(
            type=ActionType.ANALYZE,
            agent_name="test",
            target="192.168.1.0/24",
            description="Connect to API",
            requires_credentials=True,
        )
        with pytest.raises(CredentialViolation):
            validate_action("test", action, "192.168.1.0/24", session)

    def test_aws_key_detected(self):
        assert contains_credentials("AKIAIOSFODNN7EXAMPLE")

    def test_password_detected(self):
        assert contains_credentials("password=mysecret123")

    def test_private_key_detected(self):
        assert contains_credentials("-----BEGIN RSA PRIVATE KEY-----")

    def test_bearer_token_detected(self):
        assert contains_credentials("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")

    def test_clean_text_passes(self):
        assert not contains_credentials("This is a normal security assessment report.")

    def test_credential_in_command_blocked(self, session):
        action = Action(
            type=ActionType.GENERATE_COMMANDS,
            agent_name="test",
            target="192.168.1.0/24",
            description="AWS CLI command",
            command="aws s3 ls --access-key AKIAIOSFODNN7EXAMPLE",
        )
        with pytest.raises(CredentialViolation):
            validate_action("test", action, "192.168.1.0/24", session)

    def test_output_credential_redaction(self, session):
        text = "Found key: AKIAIOSFODNN7EXAMPLE in config"
        result = validate_text_output(text, session)
        assert "REDACTED" in result
        assert "AKIAIOSFODNN7EXAMPLE" not in result


# --- Rule 3: No Outbound Requests ---

class TestNetworkProtection:
    def test_network_scanning_allowed(self, session):
        """New rule: scanning is unrestricted, network access for scanning is allowed."""
        action = Action(
            type=ActionType.ANALYZE,
            agent_name="test",
            target="192.168.1.0/24",
            description="Scan target",
            requires_network=True,
        )
        # Network scanning is now unrestricted — should NOT raise
        assert validate_action("test", action, "192.168.1.0/24", session)


# --- Rule 4: Immutable Findings ---

class TestImmutability:
    def test_finding_cannot_be_removed(self, session):
        session.add_finding({
            "title": "Test Finding",
            "severity": "high",
        })
        assert len(session.findings) == 1
        # There is no delete method — this is by design
        assert not hasattr(session, "delete_finding")
        assert not hasattr(session, "remove_finding")

    def test_false_positive_preserves_finding(self, session):
        session.add_finding({
            "title": "False Positive Test",
            "severity": "medium",
        })
        session.mark_false_positive(0, "Not applicable", "test_operator")
        # Finding still exists
        assert len(session.findings) == 1
        assert session.findings[0]["status"] == "false_positive"
        assert session.findings[0]["title"] == "False Positive Test"


# --- Audit Logging ---

class TestAuditLog:
    def test_all_actions_logged(self, session):
        action = Action(
            type=ActionType.ANALYZE,
            agent_name="test",
            target="192.168.1.0/24",
            description="Test",
        )
        validate_action("test", action, "192.168.1.0/24", session)
        validated = [
            e for e in session.audit_log
            if e["event_type"] == "action_validated"
        ]
        assert len(validated) >= 1

    def test_violations_logged(self, session):
        action = Action(
            type=ActionType.ANALYZE,
            agent_name="test",
            target="10.0.0.1",
            description="Out of scope",
        )
        with pytest.raises(ScopeViolation):
            validate_action("test", action, "10.0.0.1", session)
        violations = [
            e for e in session.audit_log
            if e["event_type"] == "scope_violation"
        ]
        assert len(violations) == 1

    def test_audit_log_export(self, session):
        log = session.export_audit_log()
        assert isinstance(log, list)
        # Should have at least the target_added event
        assert len(log) >= 1
