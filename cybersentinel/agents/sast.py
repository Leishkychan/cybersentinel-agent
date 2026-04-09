"""SAST Agent — Static Application Security Testing.

Scope: Source code analysis only. No execution, no compilation,
       no dependency installation, no network access.

This agent uses regex-based pattern matching for deterministic detection
of common vulnerability patterns across multiple languages. It maps every
finding to CWE and MITRE ATT&CK.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from cybersentinel.agents.base import BaseAgent
from cybersentinel.models.finding import Finding, Severity


@dataclass
class SastRule:
    """A single SAST detection rule."""
    id: str
    title: str
    pattern: re.Pattern
    severity: Severity
    cwe: str
    description: str
    remediation: str
    mitre_techniques: list[str]
    languages: list[str]  # Which languages this rule applies to, or ["*"] for all
    confidence: str = "high"


# ============================================================
# SAST Rule Definitions — organized by vulnerability class
# ============================================================

SAST_RULES: list[SastRule] = [
    # --- SQL Injection ---
    SastRule(
        id="SAST-SQLI-001",
        title="SQL Injection — String Concatenation in Query",
        pattern=re.compile(
            r"""(?:execute|cursor\.execute|query|raw|rawQuery|createQuery|"""
            r"""sequelize\.query|\.query\s*\()\s*\(\s*(?:f['\"]|['\"].*?\s*[+%]"""
            r"""|\$\{|\.format\s*\()""",
            re.IGNORECASE,
        ),
        severity=Severity.CRITICAL,
        cwe="CWE-89",
        description="SQL query constructed using string concatenation or formatting with user-controlled input. This enables SQL injection attacks.",
        remediation="Use parameterized queries or prepared statements. Never concatenate user input into SQL strings.",
        mitre_techniques=["T1190"],
        languages=["python", "javascript", "java", "php", "ruby", "csharp"],
    ),
    SastRule(
        id="SAST-SQLI-002",
        title="SQL Injection — Raw Query with Variable",
        pattern=re.compile(
            r"""(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\s+.*?"""
            r"""(?:\+\s*\w+|\$\{?\w+\}?|%s|%d|\{0\}|'\s*\+)""",
            re.IGNORECASE,
        ),
        severity=Severity.CRITICAL,
        cwe="CWE-89",
        description="SQL statement contains variable interpolation, indicating potential SQL injection.",
        remediation="Use parameterized queries. Replace string interpolation with bind parameters.",
        mitre_techniques=["T1190"],
        languages=["*"],
    ),

    # --- Command Injection ---
    SastRule(
        id="SAST-CMDI-001",
        title="Command Injection — os.system / subprocess with User Input",
        pattern=re.compile(
            r"""(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen|check_output)"""
            r"""|exec|eval|child_process\.exec|Runtime\.getRuntime\(\)\.exec"""
            r"""|ProcessBuilder|shell_exec|system|passthru|popen)\s*\("""
            r"""(?:.*?(?:\+|%|\.format|\$\{|f['\"])|\s*['\"].*?\{)""",
            re.IGNORECASE,
        ),
        severity=Severity.CRITICAL,
        cwe="CWE-78",
        description="System command execution with potentially user-controlled input. Enables arbitrary command execution on the server.",
        remediation="Avoid shell commands with user input. Use safe APIs, allowlists, or shlex.quote() for shell escaping. Never pass user input to os.system() or subprocess with shell=True.",
        mitre_techniques=["T1059"],
        languages=["python", "javascript", "java", "php", "ruby"],
    ),
    SastRule(
        id="SAST-CMDI-002",
        title="Command Injection — shell=True in subprocess",
        pattern=re.compile(r"""subprocess\.(?:call|run|Popen|check_output)\s*\(.*?shell\s*=\s*True""", re.DOTALL),
        severity=Severity.HIGH,
        cwe="CWE-78",
        description="subprocess called with shell=True. If any argument contains user input, this enables command injection via shell metacharacters.",
        remediation="Remove shell=True. Pass command as a list of arguments instead of a string. Use shlex.split() if parsing is needed.",
        mitre_techniques=["T1059"],
        languages=["python"],
    ),

    # --- XSS ---
    SastRule(
        id="SAST-XSS-001",
        title="Cross-Site Scripting — Unescaped Output",
        pattern=re.compile(
            r"""(?:innerHTML\s*=|document\.write\s*\(|\.html\s*\(|\{\{!|<%=|"""
            r"""v-html|dangerouslySetInnerHTML|\|safe|\|raw|@Html\.Raw)""",
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        cwe="CWE-79",
        description="User-controlled data rendered without HTML escaping. Enables cross-site scripting attacks that can steal session tokens, redirect users, or modify page content.",
        remediation="Always HTML-encode output. Use framework auto-escaping. Avoid innerHTML, dangerouslySetInnerHTML, and |safe filters unless the input is explicitly sanitized.",
        mitre_techniques=["T1189"],
        languages=["javascript", "python", "java", "php", "ruby", "csharp"],
    ),

    # --- Path Traversal ---
    SastRule(
        id="SAST-PATH-001",
        title="Path Traversal — User Input in File Operations",
        pattern=re.compile(
            r"""(?:open|readFile|readFileSync|writeFile|writeFileSync|"""
            r"""createReadStream|createWriteStream|fs\.read|fopen|file_get_contents"""
            r"""|include|require|require_once|include_once)\s*\("""
            r"""(?:.*?(?:req\.|request\.|params\.|query\.|body\.|args\["""
            r"""|\+\s*\w+|\.format|\$\{|f['\"])|\s*\w+\s*\))""",
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        cwe="CWE-22",
        description="File operation uses potentially user-controlled path without sanitization. Attackers can read or write arbitrary files using ../ sequences.",
        remediation="Validate and sanitize file paths. Use os.path.realpath() to resolve symlinks and verify the resolved path is within the expected directory. Never use user input directly in file paths.",
        mitre_techniques=["T1083"],
        languages=["python", "javascript", "php", "ruby", "java"],
    ),

    # --- Hardcoded Secrets ---
    SastRule(
        id="SAST-SEC-001",
        title="Hardcoded Secret — API Key or Password in Source",
        pattern=re.compile(
            r"""(?:(?:api[_-]?key|apikey|secret[_-]?key|password|passwd|pwd"""
            r"""|token|auth[_-]?token|access[_-]?token|private[_-]?key"""
            r"""|client[_-]?secret)\s*(?:=|:)\s*['\"][^'\"]{8,}['\"])""",
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        cwe="CWE-798",
        description="Hardcoded credential or secret found in source code. If this code is committed to version control, the secret is exposed to anyone with repo access.",
        remediation="Move secrets to environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault). Never commit secrets to source code.",
        mitre_techniques=["T1552.001"],
        languages=["*"],
    ),
    SastRule(
        id="SAST-SEC-002",
        title="Hardcoded Secret — AWS Access Key Pattern",
        pattern=re.compile(r"""(?:AKIA[0-9A-Z]{16})"""),
        severity=Severity.CRITICAL,
        cwe="CWE-798",
        description="AWS Access Key ID found in source code. This can provide direct access to AWS resources.",
        remediation="Immediately rotate the key in AWS IAM. Use IAM roles or environment variables instead of hardcoded keys.",
        mitre_techniques=["T1552.001"],
        languages=["*"],
    ),

    # --- Insecure Deserialization ---
    SastRule(
        id="SAST-DESER-001",
        title="Insecure Deserialization — Pickle/YAML/Marshal",
        pattern=re.compile(
            r"""(?:pickle\.loads?|yaml\.(?:load|unsafe_load|full_load)\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)"""
            r"""|Marshal\.load|unserialize|readObject|ObjectInputStream"""
            r"""|json\.loads.*\beval\b|eval\s*\(\s*json)""",
            re.IGNORECASE,
        ),
        severity=Severity.CRITICAL,
        cwe="CWE-502",
        description="Deserialization of untrusted data can lead to remote code execution. Pickle, YAML (unsafe), and Java ObjectInputStream are common vectors.",
        remediation="Use safe deserialization: yaml.safe_load(), JSON instead of pickle, input validation before deserialization. Never deserialize untrusted data with pickle or Java ObjectInputStream.",
        mitre_techniques=["T1059"],
        languages=["python", "java", "php", "ruby"],
    ),

    # --- Insecure Crypto ---
    SastRule(
        id="SAST-CRYPTO-001",
        title="Weak Cryptography — MD5/SHA1 for Security",
        pattern=re.compile(
            r"""(?:md5|sha1|MD5|SHA1|hashlib\.md5|hashlib\.sha1"""
            r"""|MessageDigest\.getInstance\s*\(\s*['\"](?:MD5|SHA-1)['\"]"""
            r"""|CryptoJS\.MD5|CryptoJS\.SHA1)""",
        ),
        severity=Severity.MEDIUM,
        cwe="CWE-327",
        description="MD5 or SHA1 used in a security context. Both have known collision attacks and are considered cryptographically broken for security purposes.",
        remediation="Use SHA-256 or SHA-3 for hashing. Use bcrypt, scrypt, or Argon2 for password hashing. Use HMAC-SHA256 for message authentication.",
        mitre_techniques=["T1600"],
        languages=["*"],
    ),
    SastRule(
        id="SAST-CRYPTO-002",
        title="Weak Cryptography — ECB Mode or DES",
        pattern=re.compile(
            r"""(?:ECB|DES(?!ede)|Blowfish|RC4|RC2|AES\.MODE_ECB"""
            r"""|'DES'|\"DES\"|Mode\.ECB|CipherMode\.ECB)""",
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        cwe="CWE-327",
        description="Weak cipher or cipher mode detected. ECB mode leaks patterns in encrypted data. DES, RC4, and Blowfish are considered broken.",
        remediation="Use AES-256-GCM or AES-256-CBC with HMAC. Never use ECB mode, DES, RC4, or Blowfish for anything.",
        mitre_techniques=["T1600"],
        languages=["*"],
    ),

    # --- SSRF ---
    SastRule(
        id="SAST-SSRF-001",
        title="Server-Side Request Forgery — User Input in URL",
        pattern=re.compile(
            r"""(?:requests\.(?:get|post|put|delete|patch|head)|urllib\.request\.urlopen"""
            r"""|http\.get|https\.get|fetch|axios\.(?:get|post)|HttpClient"""
            r"""|WebClient|curl_exec|file_get_contents)\s*\("""
            r"""(?:.*?(?:req\.|request\.|params\.|query\.|body\."""
            r"""|\+\s*\w+|\.format|\$\{|f['\"])|\s*\w+\s*[,)])""",
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        cwe="CWE-918",
        description="HTTP request made with potentially user-controlled URL. Enables SSRF attacks that can access internal services, cloud metadata endpoints, or internal networks.",
        remediation="Validate and allowlist target URLs. Block requests to internal IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x). Use a URL parser to validate the scheme and host before making requests.",
        mitre_techniques=["T1190"],
        languages=["python", "javascript", "java", "php", "ruby", "csharp"],
    ),

    # --- XXE ---
    SastRule(
        id="SAST-XXE-001",
        title="XML External Entity Injection",
        pattern=re.compile(
            r"""(?:XMLParser|etree\.parse|etree\.fromstring|SAXParser"""
            r"""|DocumentBuilder|XMLReader|parseString|minidom\.parse"""
            r"""|xml\.dom|xml\.sax|simplexml_load_string)""",
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        cwe="CWE-611",
        description="XML parser used without explicit XXE protection. If external entity processing is not disabled, attackers can read local files, perform SSRF, or cause DoS.",
        remediation="Disable external entity processing. Python: use defusedxml. Java: set XMLConstants.FEATURE_SECURE_PROCESSING. PHP: libxml_disable_entity_loader(true).",
        mitre_techniques=["T1190"],
        languages=["python", "java", "php", "csharp"],
        confidence="medium",
    ),

    # --- Authentication Issues ---
    SastRule(
        id="SAST-AUTH-001",
        title="Hardcoded JWT Secret",
        pattern=re.compile(
            r"""(?:jwt\.(?:sign|encode|decode)|jsonwebtoken\.sign)\s*\(.*?"""
            r"""['\"][^'\"]{8,}['\"]""",
            re.IGNORECASE | re.DOTALL,
        ),
        severity=Severity.CRITICAL,
        cwe="CWE-321",
        description="JWT token signed with a hardcoded secret. Anyone with access to the source code can forge tokens.",
        remediation="Move JWT secrets to environment variables or a secrets manager. Use asymmetric signing (RS256) for production.",
        mitre_techniques=["T1078"],
        languages=["python", "javascript", "java"],
    ),

    # --- Insecure Configuration ---
    SastRule(
        id="SAST-CONF-001",
        title="Debug Mode Enabled in Production Code",
        pattern=re.compile(
            r"""(?:DEBUG\s*=\s*True|app\.debug\s*=\s*True|debug:\s*true"""
            r"""|FLASK_DEBUG\s*=\s*1|NODE_ENV\s*=\s*['\"]development['\"])""",
            re.IGNORECASE,
        ),
        severity=Severity.MEDIUM,
        cwe="CWE-489",
        description="Debug mode appears to be enabled. This can expose stack traces, internal paths, and configuration details to attackers.",
        remediation="Disable debug mode in production. Use environment variables to control debug settings. Ensure DEBUG=False and NODE_ENV=production in production deployments.",
        mitre_techniques=["T1082"],
        languages=["*"],
    ),

    # --- Open Redirect ---
    SastRule(
        id="SAST-REDIR-001",
        title="Open Redirect — User Input in Redirect",
        pattern=re.compile(
            r"""(?:redirect|res\.redirect|response\.sendRedirect"""
            r"""|header\s*\(\s*['\"]Location|HttpResponseRedirect"""
            r"""|redirect_to)\s*\("""
            r"""(?:.*?(?:req\.|request\.|params\.|query\.|body\."""
            r"""|\+\s*\w+|\$\{|f['\"])|\s*\w+\s*[,)])""",
            re.IGNORECASE,
        ),
        severity=Severity.MEDIUM,
        cwe="CWE-601",
        description="Redirect destination uses potentially user-controlled input. Attackers can redirect users to malicious phishing sites.",
        remediation="Validate redirect URLs against an allowlist of permitted domains. Use relative paths instead of full URLs. Never redirect to user-supplied URLs without validation.",
        mitre_techniques=["T1566.002"],
        languages=["python", "javascript", "java", "php", "ruby"],
    ),

    # --- CORS Misconfiguration ---
    SastRule(
        id="SAST-CORS-001",
        title="CORS — Wildcard or Reflected Origin",
        pattern=re.compile(
            r"""(?:Access-Control-Allow-Origin['\"]?\s*[:,=]\s*['\"]?\*"""
            r"""|Access-Control-Allow-Origin.*?(?:req\.|request\.|origin)"""
            r"""|cors\(\s*\{?\s*origin\s*:\s*(?:true|\*|req\.))""",
            re.IGNORECASE,
        ),
        severity=Severity.MEDIUM,
        cwe="CWE-942",
        description="CORS configured with wildcard (*) or reflected origin. This allows any website to make authenticated cross-origin requests.",
        remediation="Set Access-Control-Allow-Origin to specific trusted domains. Never use * with Access-Control-Allow-Credentials: true.",
        mitre_techniques=["T1189"],
        languages=["*"],
    ),
]


class SASTAgent(BaseAgent):
    """Analyzes source code for security vulnerabilities using pattern matching.

    Uses regex-based rules to detect common vulnerability patterns.
    Each rule maps to CWE and MITRE ATT&CK for full traceability.
    """

    name = "sast"
    description = "Static application security testing — source code analysis"

    def analyze(self, target: str, context: dict) -> list[Finding]:
        """Analyze source code for security issues.

        Args:
            target: File path or repository identifier
            context: Must include:
                - 'code': str — the source code to analyze
                - 'language': str — programming language
                - 'framework': str (optional) — framework in use
                - 'filename': str (optional) — for reporting

        Returns:
            List of security findings from code analysis
        """
        self.validate(target, f"Static analysis of {target}")
        self.log(f"Starting SAST analysis on {target}")

        findings: list[Finding] = []
        code = context.get("code", "")
        language = context.get("language", "unknown").lower()
        filename = context.get("filename", target)

        if not code.strip():
            self.log("No code provided, skipping analysis")
            return findings

        lines = code.split("\n")

        for rule in SAST_RULES:
            # Check if rule applies to this language
            if "*" not in rule.languages and language not in rule.languages:
                continue

            # Scan each line for matches
            for line_num, line in enumerate(lines, 1):
                if rule.pattern.search(line):
                    # Check for duplicates (same rule, same file)
                    already_found = any(
                        f.title == rule.title and
                        f.affected_component == f"{filename}:{line_num}"
                        for f in findings
                    )
                    if already_found:
                        continue

                    findings.append(Finding(
                        title=rule.title,
                        severity=rule.severity,
                        description=(
                            f"{rule.description}\n\n"
                            f"**Location:** `{filename}`, line {line_num}\n"
                            f"**Code:** `{line.strip()[:200]}`"
                        ),
                        affected_component=f"{filename}:{line_num}",
                        agent_source=self.name,
                        cwe_ids=[rule.cwe],
                        mitre_techniques=rule.mitre_techniques,
                        remediation=rule.remediation,
                        confidence=rule.confidence,
                        evidence=f"Pattern match: {rule.id} at {filename}:{line_num}",
                    ))

        # Multi-line pattern scan (for patterns that span lines)
        full_text = code
        for rule in SAST_RULES:
            if "*" not in rule.languages and language not in rule.languages:
                continue
            # Only re-scan with full text if the pattern has DOTALL flag
            if rule.pattern.flags & re.DOTALL:
                for match in rule.pattern.finditer(full_text):
                    line_num = full_text[:match.start()].count("\n") + 1
                    already_found = any(
                        f.title == rule.title for f in findings
                    )
                    if not already_found:
                        findings.append(Finding(
                            title=rule.title,
                            severity=rule.severity,
                            description=(
                                f"{rule.description}\n\n"
                                f"**Location:** `{filename}`, line {line_num}"
                            ),
                            affected_component=f"{filename}:{line_num}",
                            agent_source=self.name,
                            cwe_ids=[rule.cwe],
                            mitre_techniques=rule.mitre_techniques,
                            remediation=rule.remediation,
                            confidence=rule.confidence,
                            evidence=f"Pattern match: {rule.id} at {filename}:{line_num}",
                        ))

        self.log(f"SAST analysis complete on {target}: {len(findings)} findings")
        return findings
