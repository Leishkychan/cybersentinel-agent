# Phishing Investigation Reference

## Email Header Analysis

When a user provides suspicious email headers, analyze in this order:

### 1. Authentication Results
```
Authentication-Results: mx.google.com;
  dkim=pass header.d=example.com;
  spf=pass smtp.mailfrom=sender@example.com;
  dmarc=pass (p=REJECT) header.from=example.com
```

**Check:**
- **SPF**: Did the sending server's IP match the domain's SPF record? `fail` = spoofed sender
- **DKIM**: Was the email cryptographically signed by the claimed domain? `fail` = tampered or spoofed
- **DMARC**: Did both SPF and DKIM align with the From domain? `fail` = likely spoofed
- If all three pass, the email IS from the claimed domain — but the domain itself could be malicious (lookalike domains)

### 2. Received Headers (bottom to top)
Read Received headers from bottom to top — they show the email's path:
```
Received: from mail-server.attacker.com (198.51.100.5) by mx.victim.com
```
- Does the originating IP match the claimed sender domain?
- Is the originating IP on any blocklists?
- Are there mismatches between the envelope sender and the From header?

### 3. Red Flags in Headers
- **Reply-To different from From** — Attacker wants replies going elsewhere
- **X-Originating-IP from a VPN/VPS provider** — Common for phishing infrastructure
- **Envelope sender (Return-Path) doesn't match From** — Potential spoofing
- **Recently registered domain** — Check WHOIS creation date
- **Multiple Received headers through unusual servers** — Routing through compromised relays

## URL Analysis

### Deobfuscation Steps
1. **Decode URL encoding**: %20 = space, %2F = /, etc.
2. **Unshorten URLs**: Expand bit.ly, tinyurl, etc. (use redirect tracing, don't click)
3. **Check for homograph attacks**: Cyrillic а (U+0430) vs Latin a (U+0061)
4. **Look for subdomain abuse**: login.microsoft.com.attacker.com — the real domain is attacker.com
5. **Check for data URIs**: data:text/html;base64,[payload]
6. **Inspect URL parameters**: Some phishing kits pre-fill the victim's email in the URL

### URL Red Flags
- Domain doesn't match the claimed sender's organization
- IP address instead of domain name
- Excessive subdomains (security.update.microsoft.login.evil.com)
- Misspelled brand names (micr0soft, g00gle, arnazon)
- Unusual TLDs for the claimed brand (.xyz, .top, .buzz for "Microsoft")
- URL shorteners in business email context
- Embedded credentials in URL (https://user:pass@evil.com)

## Attachment Analysis

**DO NOT open suspicious attachments. Analyze metadata and structure only.**

### High-Risk File Types
| Type | Risk | Common Attack Vector |
|------|------|---------------------|
| .exe, .scr, .bat, .cmd, .ps1 | Critical | Direct execution |
| .docm, .xlsm, .pptm | High | Macro-enabled Office docs |
| .doc, .xls (legacy format) | High | Can contain macros without 'm' suffix |
| .iso, .img, .vhd | High | Container files bypass Mark-of-the-Web |
| .html, .htm | High | Credential harvesting pages |
| .lnk | High | Shortcut files can execute arbitrary commands |
| .zip (password-protected) | High | Bypasses email scanning |
| .js, .vbs, .wsf | High | Script execution |
| .pdf | Medium | Can contain JavaScript, links, embedded files |

### Indicators of Malicious Attachments
- Password provided in email body for encrypted attachment (bypasses AV)
- File extension mismatch (document.pdf.exe)
- Macro-enabled document requesting "Enable Content"
- Unusually small Office documents (often just a macro loader)
- Office documents with external template references (template injection)

## Social Engineering Patterns

### Common Phishing Pretexts
| Pretext | Targeting | Urgency Trigger |
|---------|-----------|----------------|
| Password expiration | All users | "Your password expires in 24 hours" |
| Invoice/payment | Finance | "Overdue invoice attached" |
| Shared document | All users | "John shared a document with you" |
| IT support | All users | "Action required: verify your account" |
| Executive impersonation | Finance, assistants | "I need you to process this wire transfer" |
| Shipping notification | All users | "Your package couldn't be delivered" |
| Legal/compliance | Management | "Urgent legal matter requiring attention" |
| MFA fatigue | All users | Repeated push notifications |

### Indicators of Social Engineering
- **Urgency**: "Act now", "Your account will be suspended", time pressure
- **Authority**: Claiming to be CEO, IT department, legal, law enforcement
- **Fear**: Threats of account closure, legal action, job consequences
- **Curiosity**: "You won't believe this", "Check out these photos"
- **Unusual requests**: Wire transfers, gift card purchases, sharing credentials
- **Communication channel mismatch**: CEO sending wire transfer requests via email instead of normal process

## Investigation Workflow

1. **Collect the evidence** — Full email with headers (not just forwarded)
2. **Analyze headers** — Authentication results, routing, sender validation
3. **Analyze URLs** — Deobfuscate, check reputation, identify the real domain
4. **Analyze attachments** — File type, hash, metadata (don't execute)
5. **Check for campaign indicators** — Same sender/infrastructure hitting multiple users?
6. **Map to ATT&CK** — T1566.001 (attachment), T1566.002 (link), T1566.003 (service-based)
7. **Determine scope** — How many users received this? Did anyone click/open?
8. **Respond** — Block sender/domain, quarantine matching emails, reset credentials if compromised
9. **Report** — Document for threat intelligence and user awareness
