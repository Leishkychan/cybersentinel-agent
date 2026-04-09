"""Dependency Agent — Software Composition Analysis.

Scope: Package manifests and lock files only. No package installation,
       no registry connections, no network access.

Parses real manifest files and matches against a built-in vulnerability
database. The database is static (from training data) but covers the
most commonly exploited vulnerabilities.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Optional

from cybersentinel.agents.base import BaseAgent
from cybersentinel.models.finding import Finding, Severity


@dataclass
class KnownVuln:
    """A known vulnerability in a specific package version range."""
    package: str
    ecosystem: str  # npm, pypi, maven, etc.
    cve_id: str
    affected_versions: str  # Human-readable version range
    fixed_version: str
    severity: Severity
    cvss_score: float
    cwe: str
    description: str
    mitre_techniques: list[str]
    cisa_kev: bool = False


# ============================================================
# Known Vulnerability Database (static, from training data)
# Covers the most commonly exploited packages across ecosystems.
# This is NOT exhaustive — it demonstrates the pattern.
# Future: integrate with OSV, NVD, or GitHub Advisory APIs via MCP.
# ============================================================

KNOWN_VULNS: list[KnownVuln] = [
    # --- npm / JavaScript ---
    KnownVuln("express", "npm", "CVE-2024-29041", "<4.19.2", "4.19.2",
              Severity.MEDIUM, 6.1, "CWE-601",
              "Open redirect vulnerability in Express.js res.redirect()", ["T1190"]),
    KnownVuln("lodash", "npm", "CVE-2021-23337", "<4.17.21", "4.17.21",
              Severity.HIGH, 7.2, "CWE-77",
              "Command injection via template function", ["T1059"]),
    KnownVuln("lodash", "npm", "CVE-2020-8203", "<4.17.20", "4.17.20",
              Severity.HIGH, 7.4, "CWE-1321",
              "Prototype pollution in zipObjectDeep", ["T1059"]),
    KnownVuln("axios", "npm", "CVE-2023-45857", "<1.6.0", "1.6.0",
              Severity.MEDIUM, 6.5, "CWE-352",
              "CSRF token exposure via XSRF-TOKEN cookie", ["T1189"]),
    KnownVuln("jsonwebtoken", "npm", "CVE-2022-23529", "<9.0.0", "9.0.0",
              Severity.HIGH, 7.6, "CWE-20",
              "Insecure key retrieval via secretOrPublicKey", ["T1078"]),
    KnownVuln("node-forge", "npm", "CVE-2022-24771", "<1.3.0", "1.3.0",
              Severity.HIGH, 7.5, "CWE-347",
              "Signature verification bypass in RSA PKCS#1 v1.5", ["T1600"]),
    KnownVuln("minimatch", "npm", "CVE-2022-3517", "<3.0.5", "3.0.5",
              Severity.HIGH, 7.5, "CWE-1333",
              "ReDoS via braceExpand", ["T1499"]),
    KnownVuln("qs", "npm", "CVE-2022-24999", "<6.11.0", "6.11.0",
              Severity.HIGH, 7.5, "CWE-1321",
              "Prototype pollution", ["T1059"]),
    KnownVuln("semver", "npm", "CVE-2022-25883", "<7.5.2", "7.5.2",
              Severity.HIGH, 7.5, "CWE-1333",
              "ReDoS in semver.valid()", ["T1499"]),

    # --- pypi / Python ---
    KnownVuln("django", "pypi", "CVE-2023-46695", "<4.2.7", "4.2.7",
              Severity.HIGH, 7.5, "CWE-1284",
              "Potential DoS via large values in password validators", ["T1499"]),
    KnownVuln("flask", "pypi", "CVE-2023-30861", "<2.3.2", "2.3.2",
              Severity.HIGH, 7.5, "CWE-539",
              "Session cookie set without Vary: Cookie header on redirects", ["T1539"]),
    KnownVuln("requests", "pypi", "CVE-2023-32681", "<2.31.0", "2.31.0",
              Severity.MEDIUM, 6.1, "CWE-200",
              "Proxy-Authorization header leaked on redirect to different host", ["T1557"]),
    KnownVuln("pillow", "pypi", "CVE-2023-44271", "<10.0.1", "10.0.1",
              Severity.HIGH, 7.5, "CWE-400",
              "Uncontrolled resource consumption via crafted image", ["T1499"]),
    KnownVuln("cryptography", "pypi", "CVE-2023-49083", "<41.0.6", "41.0.6",
              Severity.HIGH, 7.5, "CWE-476",
              "NULL pointer dereference when loading PKCS7 certificates", ["T1499"]),
    KnownVuln("jinja2", "pypi", "CVE-2024-22195", "<3.1.3", "3.1.3",
              Severity.MEDIUM, 6.1, "CWE-79",
              "XSS via xmlattr filter", ["T1189"]),
    KnownVuln("werkzeug", "pypi", "CVE-2023-46136", "<3.0.1", "3.0.1",
              Severity.HIGH, 7.5, "CWE-787",
              "High resource consumption via multipart form data parser", ["T1499"]),
    KnownVuln("pyyaml", "pypi", "CVE-2020-14343", "<5.4", "5.4",
              Severity.CRITICAL, 9.8, "CWE-20",
              "Arbitrary code execution via yaml.load() without SafeLoader", ["T1059"]),
    KnownVuln("numpy", "pypi", "CVE-2021-41496", "<1.22.0", "1.22.0",
              Severity.MEDIUM, 5.3, "CWE-120",
              "Buffer overflow in array_from_pyobj", ["T1059"]),

    # --- maven / Java ---
    KnownVuln("org.apache.logging.log4j:log4j-core", "maven", "CVE-2021-44228", "<2.17.0", "2.17.0",
              Severity.CRITICAL, 10.0, "CWE-917",
              "Log4Shell — Remote code execution via JNDI lookup injection", ["T1190", "T1059"], cisa_kev=True),
    KnownVuln("org.apache.logging.log4j:log4j-core", "maven", "CVE-2021-45046", "<2.17.0", "2.17.0",
              Severity.CRITICAL, 9.0, "CWE-917",
              "Log4Shell bypass — incomplete fix in 2.15.0", ["T1190", "T1059"], cisa_kev=True),
    KnownVuln("com.fasterxml.jackson.databind:jackson-databind", "maven", "CVE-2020-36518", "<2.13.2.1", "2.13.2.1",
              Severity.HIGH, 7.5, "CWE-787",
              "DoS via deeply nested JSON", ["T1499"]),
    KnownVuln("org.springframework:spring-framework", "maven", "CVE-2022-22965", "<5.3.18", "5.3.18",
              Severity.CRITICAL, 9.8, "CWE-94",
              "Spring4Shell — RCE via data binding on JDK 9+", ["T1190"], cisa_kev=True),

    # --- go ---
    KnownVuln("golang.org/x/text", "go", "CVE-2022-32149", "<0.3.8", "0.3.8",
              Severity.HIGH, 7.5, "CWE-400",
              "DoS via crafted Accept-Language header", ["T1499"]),
    KnownVuln("golang.org/x/net", "go", "CVE-2023-44487", "<0.17.0", "0.17.0",
              Severity.HIGH, 7.5, "CWE-400",
              "HTTP/2 Rapid Reset DoS", ["T1499"], cisa_kev=True),
]


# ============================================================
# Manifest Parsers
# ============================================================

def parse_requirements_txt(content: str) -> list[tuple[str, str]]:
    """Parse Python requirements.txt into (package, version) tuples."""
    deps = []
    for line in content.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Handle ==, >=, <=, ~=, !=
        match = re.match(r"^([a-zA-Z0-9_.-]+)\s*(?:[=<>~!]+\s*([0-9][0-9a-zA-Z.*-]*))?", line)
        if match:
            pkg = match.group(1).lower().replace("-", "_").replace(".", "_")
            ver = match.group(2) or "unknown"
            deps.append((pkg, ver))
    return deps


def parse_package_json(content: str) -> list[tuple[str, str]]:
    """Parse npm package.json into (package, version) tuples."""
    deps = []
    try:
        data = json.loads(content)
        for section in ["dependencies", "devDependencies", "peerDependencies"]:
            if section in data:
                for pkg, ver in data[section].items():
                    # Strip ^, ~, >=, etc.
                    clean_ver = re.sub(r"^[\^~>=<]+", "", ver)
                    deps.append((pkg.lower(), clean_ver))
    except json.JSONDecodeError:
        pass
    return deps


def parse_go_mod(content: str) -> list[tuple[str, str]]:
    """Parse Go go.mod into (module, version) tuples."""
    deps = []
    in_require = False
    for line in content.strip().split("\n"):
        line = line.strip()
        if line.startswith("require ("):
            in_require = True
            continue
        if line == ")":
            in_require = False
            continue
        if in_require or line.startswith("require "):
            match = re.match(r"(?:require\s+)?(\S+)\s+(v?[\d.]+)", line)
            if match:
                deps.append((match.group(1), match.group(2).lstrip("v")))
    return deps


def parse_pom_xml(content: str) -> list[tuple[str, str]]:
    """Parse Maven pom.xml into (groupId:artifactId, version) tuples."""
    deps = []
    # Simple regex-based parser (not full XML parsing to avoid dependencies)
    pattern = re.compile(
        r"<dependency>\s*"
        r"<groupId>([^<]+)</groupId>\s*"
        r"<artifactId>([^<]+)</artifactId>\s*"
        r"(?:<version>([^<]+)</version>)?",
        re.DOTALL
    )
    for match in pattern.finditer(content):
        group_id = match.group(1).strip()
        artifact_id = match.group(2).strip()
        version = match.group(3).strip() if match.group(3) else "unknown"
        deps.append((f"{group_id}:{artifact_id}", version))
    return deps


PARSERS = {
    "requirements.txt": parse_requirements_txt,
    "package.json": parse_package_json,
    "go.mod": parse_go_mod,
    "pom.xml": parse_pom_xml,
}


def version_lt(v1: str, v2: str) -> bool:
    """Simple version comparison. Returns True if v1 < v2."""
    try:
        parts1 = [int(x) for x in re.split(r"[.\-]", v1) if x.isdigit()]
        parts2 = [int(x) for x in re.split(r"[.\-]", v2) if x.isdigit()]
        # Pad shorter list
        max_len = max(len(parts1), len(parts2))
        parts1.extend([0] * (max_len - len(parts1)))
        parts2.extend([0] * (max_len - len(parts2)))
        return parts1 < parts2
    except (ValueError, IndexError):
        return False


class DependencyAgent(BaseAgent):
    """Analyzes dependencies for known vulnerabilities.

    Parses manifest files and matches against the built-in vuln database.
    """

    name = "dependency"
    description = "Software composition analysis — dependency CVE matching"

    def analyze(self, target: str, context: dict) -> list[Finding]:
        """Analyze dependency manifest for known vulnerabilities."""
        self.validate(target, f"Dependency analysis of {target}")
        self.log(f"Starting dependency analysis on {target}")

        findings: list[Finding] = []
        manifest = context.get("manifest", "")
        manifest_type = context.get("manifest_type", "").lower()

        if not manifest.strip():
            self.log("No manifest content provided")
            return findings

        # Determine parser
        parser = None
        if manifest_type:  # Only use manifest_type if it's not empty
            for key, parse_fn in PARSERS.items():
                if key in manifest_type or manifest_type in key:
                    parser = parse_fn
                    break

        if not parser:
            # Try to auto-detect
            if '"dependencies"' in manifest:
                parser = parse_package_json
                manifest_type = "package.json"
            elif "require (" in manifest or "module " in manifest:
                parser = parse_go_mod
                manifest_type = "go.mod"
            elif "<dependency>" in manifest:
                parser = parse_pom_xml
                manifest_type = "pom.xml"
            else:
                parser = parse_requirements_txt
                manifest_type = "requirements.txt"

        # Parse dependencies
        deps = parser(manifest)
        self.log(f"Parsed {len(deps)} dependencies from {manifest_type}")

        # Determine ecosystem
        ecosystem_map = {
            "package.json": "npm",
            "requirements.txt": "pypi",
            "go.mod": "go",
            "pom.xml": "maven",
        }
        ecosystem = ecosystem_map.get(manifest_type, "unknown")

        # Match against known vulns
        for pkg_name, pkg_version in deps:
            for vuln in KNOWN_VULNS:
                if vuln.ecosystem != ecosystem:
                    continue

                # Normalize names for comparison
                vuln_pkg = vuln.package.lower().replace("-", "_").replace(".", "_")
                dep_pkg = pkg_name.lower().replace("-", "_").replace(".", "_")

                # Check for match (exact or partial for namespaced packages)
                if vuln_pkg != dep_pkg and vuln_pkg not in dep_pkg and dep_pkg not in vuln_pkg:
                    continue

                # Check version
                if pkg_version == "unknown":
                    # Can't determine version — flag as potential
                    confidence = "low"
                else:
                    # Extract the version ceiling from affected_versions
                    ver_match = re.search(r"<([\d.]+)", vuln.affected_versions)
                    if ver_match:
                        ceiling = ver_match.group(1)
                        if not version_lt(pkg_version, ceiling):
                            continue  # Not vulnerable
                    confidence = "high"

                findings.append(Finding(
                    title=f"Vulnerable Dependency: {pkg_name} ({vuln.cve_id})",
                    severity=vuln.severity,
                    description=(
                        f"{vuln.description}\n\n"
                        f"**Package:** {pkg_name}@{pkg_version}\n"
                        f"**Affected:** {vuln.affected_versions}\n"
                        f"**Fixed in:** {vuln.fixed_version}\n"
                        f"**CISA KEV:** {'Yes — actively exploited' if vuln.cisa_kev else 'No'}"
                    ),
                    affected_component=f"{pkg_name}@{pkg_version}",
                    agent_source=self.name,
                    cve_ids=[vuln.cve_id],
                    cwe_ids=[vuln.cwe],
                    cvss_score=vuln.cvss_score,
                    cisa_kev=vuln.cisa_kev,
                    mitre_techniques=vuln.mitre_techniques,
                    remediation=f"Update {pkg_name} to version {vuln.fixed_version} or later.",
                    verification_steps=f"Check installed version: verify {pkg_name} >= {vuln.fixed_version}",
                    confidence=confidence,
                ))

        self.log(f"Dependency analysis complete: {len(findings)} findings")
        return findings
