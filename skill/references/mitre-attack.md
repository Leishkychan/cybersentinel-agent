# MITRE ATT&CK Framework Reference

## Overview

MITRE ATT&CK is a knowledge base of adversary tactics, techniques, and procedures (TTPs) based on real-world observations. It is the common language for describing adversary behavior. Every security assessment, incident, and threat model should reference ATT&CK.

## The 14 Tactics (Enterprise)

Each tactic represents a phase in the adversary's kill chain. Think of them as the "why" — the adversary's objective at each stage.

| ID | Tactic | Adversary Goal |
|----|--------|---------------|
| TA0043 | Reconnaissance | Gather info to plan the attack |
| TA0042 | Resource Development | Build infrastructure, buy tools, compromise accounts for use in attack |
| TA0001 | Initial Access | Get a foothold in the network |
| TA0002 | Execution | Run malicious code |
| TA0003 | Persistence | Maintain access across restarts/credential changes |
| TA0004 | Privilege Escalation | Get higher-level permissions |
| TA0005 | Defense Evasion | Avoid detection |
| TA0006 | Credential Access | Steal credentials |
| TA0007 | Discovery | Map out the environment |
| TA0008 | Lateral Movement | Move through the network |
| TA0009 | Collection | Gather target data |
| TA0011 | Command and Control | Communicate with compromised systems |
| TA0010 | Exfiltration | Steal data out of the network |
| TA0040 | Impact | Disrupt, destroy, or manipulate systems/data |

## High-Priority Techniques by Tactic

These are the techniques most commonly observed in real-world attacks. When assessing a system, check for exposure to these FIRST.

### TA0001 — Initial Access
- **T1566 — Phishing** (.001 Spearphishing Attachment, .002 Spearphishing Link, .003 Spearphishing via Service)
  - Detection: Email gateway logs, URL click tracking, attachment sandboxing
  - Mitigation: M1054 (Software Configuration), M1017 (User Training), M1049 (Antivirus/Antimalware)
- **T1190 — Exploit Public-Facing Application**
  - Detection: WAF logs, application logs, IDS signatures
  - Mitigation: M1051 (Update Software), M1030 (Network Segmentation), M1016 (Vulnerability Scanning)
- **T1078 — Valid Accounts** (.001 Default, .002 Domain, .003 Local, .004 Cloud)
  - Detection: Impossible travel, anomalous login times, MFA failures
  - Mitigation: M1032 (Multi-factor Authentication), M1027 (Password Policies), M1026 (Privileged Account Management)
- **T1133 — External Remote Services**
  - Detection: VPN/RDP logs, geo-anomaly detection
  - Mitigation: M1035 (Limit Access to Resource Over Network), M1032 (MFA)

### TA0002 — Execution
- **T1059 — Command and Scripting Interpreter** (.001 PowerShell, .003 Windows Command Shell, .004 Unix Shell, .006 Python, .007 JavaScript)
  - Detection: Script block logging, command-line auditing, process creation events
  - Mitigation: M1045 (Code Signing), M1042 (Disable or Remove Feature), M1038 (Execution Prevention)
- **T1203 — Exploitation for Client Execution**
  - Detection: Endpoint behavioral analysis, exploit guard events
  - Mitigation: M1051 (Update Software), M1048 (Application Isolation and Sandboxing)

### TA0003 — Persistence
- **T1053 — Scheduled Task/Job** (.005 Scheduled Task, .003 Cron)
  - Detection: Task scheduler logs, crontab monitoring
  - Mitigation: M1028 (Operating System Configuration), M1026 (Privileged Account Management)
- **T1547 — Boot or Logon Autostart Execution** (.001 Registry Run Keys, .004 Winlogon Helper DLL)
  - Detection: Registry monitoring, startup folder auditing
  - Mitigation: M1038 (Execution Prevention)
- **T1136 — Create Account** (.001 Local, .002 Domain, .003 Cloud)
  - Detection: Account creation events (4720 Windows, useradd Linux), anomalous admin activity
  - Mitigation: M1032 (MFA), M1030 (Network Segmentation)

### TA0004 — Privilege Escalation
- **T1068 — Exploitation for Privilege Escalation**
  - Detection: Process integrity level changes, unexpected SYSTEM processes
  - Mitigation: M1051 (Update Software), M1048 (Application Isolation)
- **T1548 — Abuse Elevation Control Mechanism** (.002 Bypass UAC, .003 Sudo and Sudo Caching)
  - Detection: UAC bypass indicators, sudo log anomalies
  - Mitigation: M1047 (Audit), M1028 (OS Configuration)

### TA0005 — Defense Evasion
- **T1562 — Impair Defenses** (.001 Disable or Modify Tools, .004 Disable Windows Event Logging)
  - Detection: Sysmon tamper events, service stop events, log gap detection
  - Mitigation: M1022 (Restrict File and Directory Permissions), M1024 (Restrict Registry Permissions)
- **T1070 — Indicator Removal** (.001 Clear Windows Event Logs, .002 Clear Linux Logs)
  - Detection: Log forwarding to SIEM (so clearing local logs doesn't destroy evidence), Event ID 1102
  - Mitigation: M1029 (Remote Data Storage for logs)

### TA0006 — Credential Access
- **T1003 — OS Credential Dumping** (.001 LSASS Memory, .003 NTDS, .006 DCSync)
  - Detection: LSASS access monitoring (Sysmon Event 10), DCSync replication alerts
  - Mitigation: M1043 (Credential Access Protection), M1017 (User Training), M1026 (Privileged Account Management)
- **T1110 — Brute Force** (.001 Password Guessing, .003 Password Spraying, .004 Credential Stuffing)
  - Detection: Failed login thresholds, account lockout events, impossible velocity
  - Mitigation: M1032 (MFA), M1027 (Password Policies), M1036 (Account Use Policies)

### TA0008 — Lateral Movement
- **T1021 — Remote Services** (.001 RDP, .002 SMB, .004 SSH, .006 Windows Remote Management)
  - Detection: Lateral movement correlation (login from one host immediately followed by login to another), network flow analysis
  - Mitigation: M1032 (MFA), M1035 (Limit Access), M1030 (Network Segmentation)
- **T1570 — Lateral Tool Transfer**
  - Detection: SMB file transfer anomalies, unexpected binary execution from network shares
  - Mitigation: M1037 (Filter Network Traffic)

### TA0010 — Exfiltration
- **T1041 — Exfiltration Over C2 Channel**
  - Detection: Large outbound data volumes, beaconing patterns, DNS tunneling indicators
  - Mitigation: M1031 (Network Intrusion Prevention), M1057 (Data Loss Prevention)
- **T1567 — Exfiltration Over Web Service** (.002 to Cloud Storage)
  - Detection: DLP, cloud API monitoring, unusual uploads to storage services
  - Mitigation: M1021 (Restrict Web-Based Content)

### TA0040 — Impact
- **T1486 — Data Encrypted for Impact** (Ransomware)
  - Detection: Mass file modification events, known ransomware extensions, canary files
  - Mitigation: M1053 (Data Backup), M1030 (Network Segmentation), M1049 (Antivirus)
- **T1489 — Service Stop**
  - Detection: Critical service stop events, backup service disruption
  - Mitigation: M1022 (Restrict File/Directory Permissions), M1024 (Restrict Registry)

## ATT&CK Assessment Workflow

When mapping a system or incident to ATT&CK:

1. **Identify the asset type** — Endpoint, server, cloud workload, network device, identity provider
2. **List exposed surfaces** — What services are running? What's internet-facing? What accounts exist?
3. **Map feasible techniques** — Given the software and configuration, which techniques COULD work? Don't list every technique in ATT&CK — only those relevant to the actual environment
4. **Check detection coverage** — For each feasible technique, does the org have detection in place? What data sources are being collected?
5. **Identify gaps** — Techniques with no detection = blind spots. These are the priority recommendations
6. **Recommend mitigations** — For each gap, provide the specific ATT&CK mitigation codes plus practical implementation steps

## Detection Data Sources

Key data sources and what they enable detection of:

| Data Source | Windows | Linux | Key Detections |
|------------|---------|-------|---------------|
| Process Creation | Sysmon 1, 4688 | auditd execve | Malicious execution, living-off-the-land |
| Network Connections | Sysmon 3, firewall logs | netfilter, auditd | C2 beaconing, lateral movement, exfiltration |
| File Creation/Modification | Sysmon 11, 23 | inotify, auditd | Malware drops, config changes, ransomware |
| Registry Modification | Sysmon 12/13/14 | N/A | Persistence, defense evasion |
| Authentication Events | 4624/4625/4648 | auth.log, sshd | Brute force, credential access, lateral movement |
| DNS Queries | Sysmon 22, DNS server logs | DNS resolver logs | C2 domains, DNS tunneling |
| Scheduled Tasks | 4698/4702 | cron.log | Persistence |
| Service Events | 7045, 4697 | systemd journal | Persistence, privilege escalation |

## Sigma Rule Templates

When building detection rules, use Sigma format for portability across SIEMs:

```yaml
title: [Descriptive title]
id: [UUID]
status: [experimental|test|stable]
description: [What this detects]
references:
  - [ATT&CK technique URL]
  - [Additional references]
author: CyberSentinel
date: [YYYY/MM/DD]
tags:
  - attack.[tactic]
  - attack.t[technique_id]
logsource:
  category: [process_creation|network_connection|file_event|etc]
  product: [windows|linux|etc]
detection:
  selection:
    [field]: [value]
  condition: selection
falsepositives:
  - [Known benign scenarios]
level: [informational|low|medium|high|critical]
```
