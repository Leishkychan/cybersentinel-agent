"""Technology Fingerprinting Agent — Layer 1 Reconnaissance.

Detects web server, framework, language, CDN, and CMS from HTTP headers and content.
"""

from __future__ import annotations

import re
import subprocess
from typing import TYPE_CHECKING

from cybersentinel.agents.base import BaseAgent
from cybersentinel.models.finding import Finding, Severity

if TYPE_CHECKING:
    from cybersentinel.models.session import Session


class FingerprintAgent(BaseAgent):
    """Detects technology stack from HTTP headers and HTML content."""

    name = "fingerprint"
    description = "Technology fingerprinting — detects web server, framework, language, CDN"

    def __init__(self, session: Session):
        super().__init__(session)

    def analyze(self, target: str, context: dict) -> list[Finding]:
        """Fingerprint technology stack of target.

        Args:
            target: The target URL or domain
            context: Additional context

        Returns:
            List of Finding objects for detected technologies
        """
        self.validate(target, f"Technology fingerprinting of {target}")
        self.log(f"Starting technology fingerprinting on {target}")

        findings: list[Finding] = []

        # Ensure URL is properly formatted
        url = target if target.startswith(('http://', 'https://')) else f"http://{target}"

        # Get HTTP headers
        headers = self._get_http_headers(url)
        if headers:
            findings.extend(self._analyze_headers(url, headers))

        # Get HTML content for more fingerprinting
        html_content = self._get_html_content(url)
        if html_content:
            findings.extend(self._analyze_html(url, html_content))

        self.log(f"Technology fingerprinting complete: {len(findings)} technologies identified")
        return findings

    def _get_http_headers(self, url: str) -> dict:
        """Fetch HTTP response headers using curl."""
        headers = {}

        try:
            cmd = ["curl", "-sI", url]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
            )

            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip()] = value.strip()

        except FileNotFoundError:
            self.log("curl not found on system")
        except subprocess.TimeoutExpired:
            self.log("curl timed out")
        except Exception as e:
            self.log(f"curl error: {str(e)}")

        return headers

    def _get_html_content(self, url: str) -> str:
        """Fetch HTML content using curl."""
        content = ""

        try:
            cmd = ["curl", "-s", "-m", "10", url]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
            )

            if result.returncode == 0:
                content = result.stdout

        except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
            pass

        return content

    def _analyze_headers(self, url: str, headers: dict) -> list[Finding]:
        """Analyze HTTP headers for technology indicators."""
        findings = []

        # Web Server Detection
        server_header = headers.get("Server", "")
        if server_header:
            server_name = server_header.split('/')[0].strip()
            severity = Severity.LOW if server_name.lower() in ['nginx', 'apache'] else Severity.LOW

            findings.append(Finding(
                title=f"Web Server: {server_header}",
                severity=severity,
                description=f"Web server detected: {server_header}",
                affected_component=url,
                agent_source=self.name,
                mitre_tactics=["Reconnaissance"],
                mitre_techniques=["T1592"],  # Gather Victim Host Information
                evidence=f"Server header: {server_header}",
                confidence="high",
            ))

            # Check for version disclosure
            if re.search(r'Apache/|Nginx/|IIS/', server_header):
                findings.append(Finding(
                    title=f"Version Disclosure: {server_header}",
                    severity=Severity.LOW,
                    description=f"Server version is exposed in response headers: {server_header}. "
                                f"This aids attackers in version-specific exploitation.",
                    affected_component=url,
                    agent_source=self.name,
                    mitre_tactics=["Reconnaissance"],
                    mitre_techniques=["T1592"],
                    remediation="Configure web server to hide version information (ServerTokens/server_tokens off)",
                    evidence=f"Server header: {server_header}",
                    confidence="high",
                ))

        # Application Framework Detection
        app_headers = {
            "X-Powered-By": ("Framework/Language", Severity.LOW),
            "X-AspNet-Version": ("ASP.NET", Severity.LOW),
            "X-Runtime-Version": ("Runtime", Severity.LOW),
            "X-UA-Compatible": ("IE Compatibility Mode", Severity.INFO),
        }

        for header_name, (tech_type, sev) in app_headers.items():
            if header_name in headers:
                value = headers[header_name]
                findings.append(Finding(
                    title=f"{tech_type}: {value}",
                    severity=sev,
                    description=f"{tech_type} detected via header: {header_name} = {value}",
                    affected_component=url,
                    agent_source=self.name,
                    mitre_tactics=["Reconnaissance"],
                    mitre_techniques=["T1592"],
                    evidence=f"Header: {header_name}",
                    confidence="high",
                ))

        # CDN Detection
        cdn_headers = {
            "CF-RAY": "Cloudflare CDN",
            "X-Amz-Cf-Id": "AWS CloudFront",
            "X-Cache": "Caching Layer",
            "X-Fastly-Request-ID": "Fastly CDN",
            "Akamai-Request-ID": "Akamai CDN",
        }

        for header_name, cdn_name in cdn_headers.items():
            if header_name in headers:
                findings.append(Finding(
                    title=f"CDN Detected: {cdn_name}",
                    severity=Severity.INFO,
                    description=f"Target is using {cdn_name} (header: {header_name})",
                    affected_component=url,
                    agent_source=self.name,
                    mitre_tactics=["Reconnaissance"],
                    mitre_techniques=["T1592"],
                    evidence=f"Header: {header_name} = {headers[header_name]}",
                    confidence="high",
                ))

        # Security Header Detection
        security_headers = [
            ("Strict-Transport-Security", "HSTS Enabled", Severity.INFO),
            ("X-Frame-Options", "Clickjacking Protection", Severity.INFO),
            ("X-Content-Type-Options", "MIME Type Sniffing Protection", Severity.INFO),
            ("Content-Security-Policy", "CSP Policy", Severity.INFO),
        ]

        for header_name, description, sev in security_headers:
            if header_name in headers:
                findings.append(Finding(
                    title=f"Security Header: {description}",
                    severity=sev,
                    description=f"{description} is configured: {headers[header_name]}",
                    affected_component=url,
                    agent_source=self.name,
                    mitre_tactics=["Reconnaissance"],
                    mitre_techniques=["T1592"],
                    evidence=f"Header: {header_name}",
                    confidence="high",
                ))

        return findings

    def _analyze_html(self, url: str, content: str) -> list[Finding]:
        """Analyze HTML content for technology indicators."""
        findings = []

        # CMS Detection
        cms_indicators = {
            r'wp-content': ("WordPress", "Popular CMS"),
            r'joomla': ("Joomla", "CMS"),
            r'drupal': ("Drupal", "CMS"),
            r'static\.drupal\.org': ("Drupal", "CMS"),
            r'generator.*wordpress': ("WordPress", "CMS"),
            r'generator.*joomla': ("Joomla", "CMS"),
            r'generator.*drupal': ("Drupal", "CMS"),
            r'shopify': ("Shopify", "E-commerce Platform"),
            r'magento': ("Magento", "E-commerce Platform"),
        }

        for pattern, (cms_name, cms_type) in cms_indicators.items():
            if re.search(pattern, content, re.IGNORECASE):
                findings.append(Finding(
                    title=f"CMS Detected: {cms_name}",
                    severity=Severity.LOW,
                    description=f"{cms_type} detected: {cms_name}. This narrows the potential vulnerabilities "
                                f"to those specific to this platform.",
                    affected_component=url,
                    agent_source=self.name,
                    mitre_tactics=["Reconnaissance"],
                    mitre_techniques=["T1592"],
                    evidence=f"Pattern matched: {pattern}",
                    confidence="high",
                ))
                break  # Only report one CMS to avoid duplicates

        # JavaScript Framework Detection
        js_frameworks = {
            r'angular': "Angular",
            r'react': "React",
            r'vue': "Vue.js",
            r'ember': "Ember.js",
            r'backbone': "Backbone.js",
        }

        for pattern, framework_name in js_frameworks.items():
            if re.search(rf'{pattern}\.js|{pattern}/|{pattern}-', content, re.IGNORECASE):
                findings.append(Finding(
                    title=f"JavaScript Framework: {framework_name}",
                    severity=Severity.INFO,
                    description=f"JavaScript framework detected: {framework_name}",
                    affected_component=url,
                    agent_source=self.name,
                    mitre_tactics=["Reconnaissance"],
                    mitre_techniques=["T1592"],
                    evidence=f"Pattern matched in HTML/JS: {pattern}",
                    confidence="high",
                ))

        # Generator Meta Tag
        generator_match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\'](.*?)["\']', content)
        if generator_match:
            generator = generator_match.group(1)
            findings.append(Finding(
                title=f"Generator Meta Tag: {generator}",
                severity=Severity.INFO,
                description=f"Generator detected: {generator}. Technology information disclosed via meta tag.",
                affected_component=url,
                agent_source=self.name,
                mitre_tactics=["Reconnaissance"],
                mitre_techniques=["T1592"],
                evidence=f"Meta tag: generator={generator}",
                confidence="high",
            ))

        # Cookie Detection
        set_cookie_pattern = r'Set-Cookie:\s*([^;]+)'
        cookies = re.findall(set_cookie_pattern, content, re.IGNORECASE)

        cookie_tech = {
            'PHPSESSID': ('PHP', Severity.LOW),
            'JSESSIONID': ('Java', Severity.LOW),
            'ASPSESSIONID': ('ASP.NET', Severity.LOW),
            'RAILS_SESSION': ('Ruby on Rails', Severity.LOW),
        }

        for cookie_name, (tech_name, sev) in cookie_tech.items():
            if any(cookie_name in c for c in cookies):
                findings.append(Finding(
                    title=f"Server Technology: {tech_name}",
                    severity=sev,
                    description=f"Server technology detected from session cookie: {tech_name} ({cookie_name})",
                    affected_component=url,
                    agent_source=self.name,
                    mitre_tactics=["Reconnaissance"],
                    mitre_techniques=["T1592"],
                    evidence=f"Session cookie: {cookie_name}",
                    confidence="high",
                ))

        # Check for common tech-specific paths
        tech_paths = {
            r'/wp-admin/': ('WordPress', Severity.LOW),
            r'/administrator/': ('Joomla', Severity.LOW),
            r'/admin/': ('Generic CMS', Severity.LOW),
            r'/phpmyadmin/': ('PHP + MySQL', Severity.MEDIUM),
            r'\.git/config': ('Git Repository Exposed', Severity.HIGH),
            r'\.env': ('Environment File Exposed', Severity.CRITICAL),
        }

        for path, (tech, sev) in tech_paths.items():
            if re.search(path, content):
                findings.append(Finding(
                    title=f"Potential Path: {tech}",
                    severity=sev,
                    description=f"Pattern '{path}' found, suggesting: {tech}",
                    affected_component=url,
                    agent_source=self.name,
                    mitre_tactics=["Reconnaissance"],
                    mitre_techniques=["T1592"],
                    evidence=f"Path pattern in content: {path}",
                    confidence="medium",
                ))

        return findings
