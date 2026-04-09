"""Tests for the Config Agent — Misconfiguration Detection.

Tests verify detection of security misconfigurations in nginx, sshd, Docker,
Terraform, and AWS IAM configurations.
"""

import pytest

from cybersentinel.agents.config import ConfigAgent
from cybersentinel.models.finding import Severity
from cybersentinel.models.session import Session, SessionMode


@pytest.fixture
def session():
    """Create a test session with one approved target."""
    s = Session(mode=SessionMode.GUIDED)
    s.add_target("test-target", approved_by="test_operator")
    return s


@pytest.fixture
def config_agent(session):
    """Create a Config agent instance."""
    return ConfigAgent(session)


class TestNginxConfigAnalysis:
    """Test nginx configuration security checks."""

    def test_nginx_directory_listing_enabled(self, config_agent, session):
        """Detect nginx with autoindex on (directory listing)."""
        config = """
server {
    listen 80;
    server_name example.com;
    autoindex on;
    location / {
        root /var/www;
    }
}
        """
        findings = config_agent.analyze("test-target", {
            "config": config,
            "config_type": "nginx"
        })

        assert len(findings) > 0
        finding = next((f for f in findings if "Directory Listing" in f.title), None)
        assert finding is not None
        assert finding.severity == Severity.MEDIUM
        assert "CWE-548" in finding.cwe_ids

    def test_nginx_missing_security_headers(self, config_agent, session):
        """Detect nginx missing security headers."""
        config = """
server {
    listen 443 ssl;
    server_name example.com;
    ssl_certificate /etc/ssl/cert.pem;
    ssl_certificate_key /etc/ssl/key.pem;
    location / {
        proxy_pass http://app:3000;
    }
}
        """
        findings = config_agent.analyze("test-target", {
            "config": config,
            "config_type": "nginx"
        })

        # Should detect missing security headers
        assert len(findings) > 0
        missing_header_findings = [f for f in findings if "Missing" in f.title and "Header" in f.title]
        assert len(missing_header_findings) > 0

    def test_nginx_http_without_redirect(self, config_agent, session):
        """Detect nginx listening on HTTP without HTTPS redirect."""
        config = """
server {
    listen 80;
    server_name example.com;
    location / {
        root /var/www;
    }
}
        """
        findings = config_agent.analyze("test-target", {
            "config": config,
            "config_type": "nginx"
        })

        assert len(findings) > 0
        finding = next((f for f in findings if "HTTPS Redirect" in f.title), None)
        assert finding is not None
        assert finding.severity == Severity.HIGH

    def test_nginx_server_tokens_disclosure(self, config_agent, session):
        """Detect nginx version disclosure."""
        config = """
server {
    listen 443 ssl;
    server_name example.com;
}
        """
        findings = config_agent.analyze("test-target", {
            "config": config,
            "config_type": "nginx"
        })

        # Should detect missing "server_tokens off"
        assert any("Server Version" in f.title for f in findings)

    def test_nginx_php_in_upload_dir(self, config_agent, session):
        """Detect PHP execution enabled in upload directory."""
        config = """
server {
    location /uploads {
        fastcgi_pass 127.0.0.1:9000;
    }
}
        """
        findings = config_agent.analyze("test-target", {
            "config": config,
            "config_type": "nginx"
        })

        assert len(findings) > 0
        finding = next((f for f in findings if "PHP Execution" in f.title), None)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL

    def test_nginx_secure_config_headers(self, config_agent, session):
        """Secure nginx config with headers should have fewer findings."""
        config = """
server {
    listen 443 ssl http2;
    server_name example.com;
    ssl_certificate /etc/ssl/cert.pem;
    ssl_certificate_key /etc/ssl/key.pem;

    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-Content-Type-Options "nosniff";
    add_header X-XSS-Protection "1; mode=block";
    add_header Content-Security-Policy "default-src 'self'";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";

    server_tokens off;
    autoindex off;

    location / {
        proxy_pass http://app:3000;
    }
}
        """
        findings = config_agent.analyze("test-target", {
            "config": config,
            "config_type": "nginx"
        })

        # Should have no security header or critical findings
        critical_findings = [f for f in findings if f.severity in [Severity.CRITICAL, Severity.HIGH]]
        # Allow for some low/medium findings but critical should be minimal
        assert len(critical_findings) == 0


class TestSshdConfigAnalysis:
    """Test SSH daemon configuration security checks."""

    def test_sshd_root_login_permitted(self, config_agent, session):
        """Detect sshd with PermitRootLogin yes."""
        config = """
Port 22
PermitRootLogin yes
PasswordAuthentication yes
        """
        findings = config_agent.analyze("test-target", {
            "config": config,
            "config_type": "sshd"
        })

        assert len(findings) > 0
        finding = next((f for f in findings if "Root Login" in f.title), None)
        assert finding is not None
        assert finding.severity == Severity.HIGH
        assert "CWE-250" in finding.cwe_ids

    def test_sshd_password_authentication_enabled(self, config_agent, session):
        """Detect sshd with PasswordAuthentication yes."""
        config = """
Port 22
PermitRootLogin no
PasswordAuthentication yes
        """
        findings = config_agent.analyze("test-target", {
            "config": config,
            "config_type": "sshd"
        })

        assert len(findings) > 0
        finding = next((f for f in findings if "Password Authentication" in f.title), None)
        assert finding is not None
        assert finding.severity == Severity.HIGH

    def test_sshd_empty_passwords_permitted(self, config_agent, session):
        """Detect sshd with PermitEmptyPasswords yes."""
        config = """
PermitEmptyPasswords yes
        """
        findings = config_agent.analyze("test-target", {
            "config": config,
            "config_type": "sshd"
        })

        assert len(findings) > 0
        finding = next((f for f in findings if "Empty Passwords" in f.title), None)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL

    def test_sshd_protocol_version_1(self, config_agent, session):
        """Detect sshd with Protocol 1 enabled."""
        config = """
Protocol 1
Port 22
        """
        findings = config_agent.analyze("test-target", {
            "config": config,
            "config_type": "sshd"
        })

        assert len(findings) > 0
        finding = next((f for f in findings if "Protocol" in f.title), None)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL

    def test_sshd_x11_forwarding_enabled(self, config_agent, session):
        """Detect sshd with X11Forwarding enabled."""
        config = """
X11Forwarding yes
        """
        findings = config_agent.analyze("test-target", {
            "config": config,
            "config_type": "sshd"
        })

        assert len(findings) > 0
        finding = next((f for f in findings if "X11" in f.title), None)
        assert finding is not None
        assert finding.severity == Severity.LOW

    def test_sshd_secure_config(self, config_agent, session):
        """Secure sshd config should have no critical findings."""
        config = """
Port 22
Protocol 2
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 60
        """
        findings = config_agent.analyze("test-target", {
            "config": config,
            "config_type": "sshd"
        })

        # Should have no critical findings
        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) == 0


class TestDockerfileAnalysis:
    """Test Dockerfile security checks."""

    def test_dockerfile_runs_as_root(self, config_agent, session):
        """Detect Dockerfile running container as root."""
        dockerfile = """
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y python3
COPY app.py /app/
WORKDIR /app
CMD ["python3", "app.py"]
        """
        findings = config_agent.analyze("test-target", {
            "config": dockerfile,
            "config_type": "dockerfile"
        })

        assert len(findings) > 0
        finding = next((f for f in findings if "root" in f.title.lower()), None)
        assert finding is not None
        assert finding.severity == Severity.HIGH

    def test_dockerfile_uses_latest_tag(self, config_agent, session):
        """Detect Dockerfile using 'latest' base image tag."""
        dockerfile = """
FROM python:latest
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . /app
WORKDIR /app
USER appuser
CMD ["python", "app.py"]
        """
        findings = config_agent.analyze("test-target", {
            "config": dockerfile,
            "config_type": "dockerfile"
        })

        assert len(findings) > 0
        finding = next((f for f in findings if "latest" in f.title.lower()), None)
        assert finding is not None
        assert finding.severity == Severity.MEDIUM

    def test_dockerfile_copy_entire_context(self, config_agent, session):
        """Detect Dockerfile copying entire context with COPY . ."""
        dockerfile = """
FROM python:3.11
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
CMD ["python", "app.py"]
        """
        findings = config_agent.analyze("test-target", {
            "config": dockerfile,
            "config_type": "dockerfile"
        })

        assert len(findings) > 0
        finding = next((f for f in findings if "COPY ." in f.title or "entire context" in f.description.lower()), None)
        assert finding is not None

    def test_dockerfile_secrets_in_env(self, config_agent, session):
        """Detect Dockerfile with secrets in ENV directive."""
        dockerfile = """
FROM ubuntu:22.04
ENV DATABASE_PASSWORD="secret123"
ENV API_KEY="AKIAIOSFODNN7EXAMPLE"
RUN apt-get install -y python3
        """
        findings = config_agent.analyze("test-target", {
            "config": dockerfile,
            "config_type": "dockerfile"
        })

        assert len(findings) > 0
        finding = next((f for f in findings if "Secrets" in f.title and "ENV" in f.title), None)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL

    def test_dockerfile_using_add(self, config_agent, session):
        """Detect Dockerfile using ADD instead of COPY."""
        dockerfile = """
FROM ubuntu:22.04
ADD . /app
WORKDIR /app
        """
        findings = config_agent.analyze("test-target", {
            "config": dockerfile,
            "config_type": "dockerfile"
        })

        assert len(findings) > 0
        finding = next((f for f in findings if "ADD" in f.title), None)
        assert finding is not None

    def test_dockerfile_secure(self, config_agent, session):
        """Secure Dockerfile with best practices."""
        dockerfile = """
FROM python:3.11-slim
RUN useradd -m appuser
COPY requirements.txt /app/
WORKDIR /app
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=appuser:appuser . /app
USER appuser
CMD ["python", "app.py"]
        """
        findings = config_agent.analyze("test-target", {
            "config": dockerfile,
            "config_type": "dockerfile"
        })

        # Should have minimal/no critical findings
        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) == 0


class TestTerraformAnalysis:
    """Test Terraform configuration security checks."""

    def test_terraform_s3_without_encryption(self, config_agent, session):
        """Detect S3 bucket without encryption."""
        tf = """
resource "aws_s3_bucket" "my_bucket" {
  bucket = "my-bucket"
  acl    = "private"
}
        """
        findings = config_agent.analyze("test-target", {
            "config": tf,
            "config_type": "terraform"
        })

        assert len(findings) > 0
        finding = next((f for f in findings if "S3" in f.title and "Encryption" in f.title), None)
        assert finding is not None
        assert finding.severity == Severity.HIGH

    def test_terraform_security_group_open_world(self, config_agent, session):
        """Detect security group open to world (0.0.0.0/0)."""
        tf = """
resource "aws_security_group" "web" {
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
        """
        findings = config_agent.analyze("test-target", {
            "config": tf,
            "config_type": "terraform"
        })

        assert len(findings) > 0
        finding = next((f for f in findings if "Security Group" in f.title or "0.0.0.0" in f.description), None)
        assert finding is not None
        assert finding.severity == Severity.HIGH

    def test_terraform_hardcoded_credentials(self, config_agent, session):
        """Detect hardcoded AWS credentials in Terraform."""
        tf = """
provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}
        """
        findings = config_agent.analyze("test-target", {
            "config": tf,
            "config_type": "terraform"
        })

        assert len(findings) > 0
        finding = next((f for f in findings if "Hardcoded" in f.title and "Credentials" in f.title), None)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL

    def test_terraform_rds_without_encryption(self, config_agent, session):
        """Detect RDS instance without encryption at rest."""
        tf = """
resource "aws_db_instance" "mysql" {
  identifier       = "my-database"
  engine           = "mysql"
  instance_class   = "db.t3.micro"
  allocated_storage = 20
}
        """
        findings = config_agent.analyze("test-target", {
            "config": tf,
            "config_type": "terraform"
        })

        assert len(findings) > 0
        finding = next((f for f in findings if "RDS" in f.title and "Encryption" in f.title), None)
        assert finding is not None
        assert finding.severity == Severity.HIGH

    def test_terraform_rds_publicly_accessible(self, config_agent, session):
        """Detect RDS publicly accessible."""
        tf = """
resource "aws_db_instance" "mysql" {
  identifier            = "my-database"
  engine                = "mysql"
  publicly_accessible   = true
  storage_encrypted     = true
}
        """
        findings = config_agent.analyze("test-target", {
            "config": tf,
            "config_type": "terraform"
        })

        assert len(findings) > 0
        finding = next((f for f in findings if "Publicly Accessible" in f.title), None)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL

    def test_terraform_secure(self, config_agent, session):
        """Secure Terraform configuration."""
        tf = """
resource "aws_s3_bucket" "secure" {
  bucket = "my-secure-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "example" {
  bucket = aws_s3_bucket.secure.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_security_group" "secure" {
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_db_instance" "secure" {
  identifier            = "secure-db"
  storage_encrypted     = true
  publicly_accessible   = false
}
        """
        findings = config_agent.analyze("test-target", {
            "config": tf,
            "config_type": "terraform"
        })

        # Should have no critical findings
        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) == 0


class TestAwsIamAnalysis:
    """Test AWS IAM policy security checks."""

    def test_iam_full_admin_access(self, config_agent, session):
        """Detect IAM policy with full admin access (Action: *, Resource: *)."""
        policy = """{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}"""
        findings = config_agent.analyze("test-target", {
            "config": policy,
            "config_type": "aws_iam"
        })

        assert len(findings) > 0
        finding = next((f for f in findings if "Full Admin" in f.title or "Action: *" in f.title), None)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL

    def test_iam_full_s3_access(self, config_agent, session):
        """Detect IAM policy with full S3 access."""
        policy = """{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:*",
      "Resource": "*"
    }
  ]
}"""
        findings = config_agent.analyze("test-target", {
            "config": policy,
            "config_type": "aws_iam"
        })

        assert len(findings) > 0
        finding = next((f for f in findings if "S3" in f.title), None)
        assert finding is not None
        assert finding.severity == Severity.HIGH

    def test_iam_sensitive_action_without_condition(self, config_agent, session):
        """Detect sensitive IAM actions without conditions."""
        policy = """{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "iam:*",
      "Resource": "*"
    }
  ]
}"""
        findings = config_agent.analyze("test-target", {
            "config": policy,
            "config_type": "aws_iam"
        })

        assert len(findings) > 0
        finding = next((f for f in findings if "Sensitive Action" in f.title or "Condition" in f.title), None)
        assert finding is not None or any("iam" in f.description.lower() for f in findings)

    def test_iam_secure_policy(self, config_agent, session):
        """Secure IAM policy with least privilege."""
        policy = """{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::my-bucket/*",
      "Condition": {
        "IpAddress": {
          "aws:SourceIp": "10.0.0.0/8"
        }
      }
    }
  ]
}"""
        findings = config_agent.analyze("test-target", {
            "config": policy,
            "config_type": "aws_iam"
        })

        # Should have no critical/high findings
        critical_findings = [f for f in findings if f.severity in [Severity.CRITICAL, Severity.HIGH]]
        assert len(critical_findings) == 0


class TestAutoDetection:
    """Test auto-detection of configuration type."""

    def test_auto_detect_nginx(self, config_agent, session):
        """Auto-detect nginx configuration."""
        config = """
server {
    listen 80;
    autoindex on;
}
        """
        findings = config_agent.analyze("test-target", {
            "config": config,
            "config_type": ""  # Empty, should auto-detect
        })

        assert len(findings) > 0

    def test_auto_detect_sshd(self, config_agent, session):
        """Auto-detect sshd configuration."""
        config = "PermitRootLogin yes\n"
        findings = config_agent.analyze("test-target", {
            "config": config,
            "config_type": ""  # Empty, should auto-detect
        })

        assert len(findings) > 0

    def test_auto_detect_dockerfile(self, config_agent, session):
        """Auto-detect Dockerfile."""
        config = "FROM ubuntu:latest\nRUN apt-get install python3\n"
        findings = config_agent.analyze("test-target", {
            "config": config,
            "config_type": ""  # Empty, should auto-detect
        })

        assert len(findings) > 0

    def test_auto_detect_terraform(self, config_agent, session):
        """Auto-detect Terraform configuration."""
        config = 'resource "aws_s3_bucket" "test" { bucket = "test" }\n'
        findings = config_agent.analyze("test-target", {
            "config": config,
            "config_type": ""  # Empty, should auto-detect
        })

        assert len(findings) > 0

    def test_auto_detect_iam_policy(self, config_agent, session):
        """Auto-detect AWS IAM policy."""
        config = '{"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}\n'
        findings = config_agent.analyze("test-target", {
            "config": config,
            "config_type": ""  # Empty, should auto-detect
        })

        assert len(findings) > 0


class TestEmptyConfigs:
    """Test handling of empty configurations."""

    def test_empty_config_no_findings(self, config_agent, session):
        """Empty config should produce no findings."""
        findings = config_agent.analyze("test-target", {
            "config": "",
            "config_type": "nginx"
        })

        assert len(findings) == 0

    def test_whitespace_only_config(self, config_agent, session):
        """Whitespace-only config should produce no findings."""
        findings = config_agent.analyze("test-target", {
            "config": "  \n\n  \n  ",
            "config_type": "nginx"
        })

        assert len(findings) == 0


class TestFindingMetadata:
    """Test that config findings have correct metadata."""

    def test_finding_has_cwe(self, config_agent, session):
        """All findings must have CWE IDs."""
        config = "PermitRootLogin yes\n"
        findings = config_agent.analyze("test-target", {
            "config": config,
            "config_type": "sshd"
        })

        for finding in findings:
            assert len(finding.cwe_ids) > 0
            assert all(cwe.startswith("CWE-") for cwe in finding.cwe_ids)

    def test_finding_has_remediation(self, config_agent, session):
        """All findings must have remediation guidance."""
        config = "autoindex on;\n"
        findings = config_agent.analyze("test-target", {
            "config": config,
            "config_type": "nginx"
        })

        for finding in findings:
            assert finding.remediation
            assert len(finding.remediation) > 0

    def test_finding_has_mitre_techniques(self, config_agent, session):
        """All findings should have MITRE ATT&CK mapping."""
        config = "PermitRootLogin yes\n"
        findings = config_agent.analyze("test-target", {
            "config": config,
            "config_type": "sshd"
        })

        for finding in findings:
            assert len(finding.mitre_techniques) > 0
