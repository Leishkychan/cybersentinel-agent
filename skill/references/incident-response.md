# Incident Response Reference (NIST SP 800-61 Based)

## IR Phases

### Phase 1: Preparation
Before the incident:
- IR plan documented and tested
- Contact list (IR team, legal, comms, management, law enforcement)
- Forensic toolkit ready (imaging tools, write blockers, chain of custody forms)
- Logging infrastructure confirmed operational
- Backup integrity verified
- Communication channels established (out-of-band if primary is compromised)

### Phase 2: Detection & Analysis

**Classification:**
| Category | Examples | Initial Severity |
|----------|----------|-----------------|
| Malware | Ransomware, trojan, worm, cryptominer | High-Critical |
| Unauthorized Access | Compromised credentials, brute force success | High |
| Data Breach | Confirmed data exfiltration or exposure | Critical |
| DoS/DDoS | Service disruption | Medium-High |
| Insider Threat | Unauthorized data access by employee | High-Critical |
| Web Compromise | Defacement, webshell, injection | Medium-High |
| Phishing | Credential harvest, malware delivery | Medium |

**Triage checklist:**
1. What systems are affected? Scope the blast radius
2. Is the attack ongoing or historical?
3. What's the business impact RIGHT NOW?
4. Is data at risk of exfiltration or destruction?
5. Are there legal/regulatory notification requirements?
6. Map to ATT&CK — what tactic/technique is the adversary using?

**Evidence Collection Priority (volatile first):**
1. Running processes and network connections
2. Memory (RAM dump)
3. Logged-in users and active sessions
4. Network traffic captures
5. System logs
6. Disk images
7. Configuration files

```bash
# Linux — Quick volatile data collection
date > /tmp/ir_evidence/timestamp.txt
ps auxf > /tmp/ir_evidence/processes.txt
netstat -tulnp > /tmp/ir_evidence/network.txt
ss -tupna > /tmp/ir_evidence/sockets.txt
who > /tmp/ir_evidence/users.txt
last -a > /tmp/ir_evidence/logins.txt
cat /proc/*/cmdline | tr '\0' ' ' > /tmp/ir_evidence/cmdlines.txt
ip a > /tmp/ir_evidence/network_config.txt
iptables -L -n -v > /tmp/ir_evidence/firewall.txt
find /tmp /var/tmp /dev/shm -type f -mtime -7 > /tmp/ir_evidence/recent_tmp.txt

# Windows — Quick volatile data collection (PowerShell)
Get-Date | Out-File C:\IR\timestamp.txt
Get-Process | Out-File C:\IR\processes.txt
Get-NetTCPConnection | Out-File C:\IR\network.txt
query user | Out-File C:\IR\users.txt
Get-WinEvent -LogName Security -MaxEvents 1000 | Out-File C:\IR\security_events.txt
```

### Phase 3: Containment

**Short-term containment** (stop the bleeding):
- Isolate affected hosts (network segmentation, EDR isolation, firewall rules)
- Block known malicious IPs/domains at firewall/proxy
- Disable compromised accounts
- Redirect DNS for C2 domains to sinkhole

**Long-term containment** (stabilize while you prepare eradication):
- Patch the exploited vulnerability
- Apply additional monitoring to affected segment
- Implement temporary compensating controls
- Preserve evidence before making changes (image first, then contain)

**DO NOT:**
- Shut down systems without collecting volatile evidence first
- Alert the attacker by making obvious changes (if dealing with APT)
- Wipe and reimage before understanding the full scope
- Assume one compromised host = total scope

### Phase 4: Eradication
- Remove malware and attacker persistence mechanisms
- Patch all exploited vulnerabilities
- Reset ALL credentials that may have been exposed (not just confirmed compromised ones)
- Rebuild compromised systems from known-good images
- Verify eradication — scan for remaining IOCs

### Phase 5: Recovery
- Restore from clean backups (verify backup integrity first — attackers target backups)
- Monitor recovered systems closely for 30-90 days
- Gradual return to production with enhanced monitoring
- Confirm business operations are fully restored

### Phase 6: Post-Incident / Lessons Learned
- Blameless postmortem within 1-2 weeks
- Document timeline, root cause, impact, response actions
- Identify what worked and what didn't
- Update IR playbooks based on findings
- Report metrics: time to detect, time to contain, time to eradicate
- ATT&CK mapping of the full incident for threat intelligence

## Notification Requirements

| Regulation | Requirement | Timeline |
|-----------|-------------|----------|
| GDPR | Report to supervisory authority if personal data involved | 72 hours |
| HIPAA | Report to HHS if PHI involved | 60 days (but sooner is expected) |
| PCI DSS | Notify acquiring bank and card brands | Immediately upon discovery |
| SEC (public companies) | Material cybersecurity incidents must be disclosed | 4 business days |
| State breach notification | Varies by state — check applicable laws | Varies (24hrs to 90 days) |

Always involve legal counsel before making external notifications.
