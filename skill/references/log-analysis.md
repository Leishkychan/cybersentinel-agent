# Log Analysis & IOC Detection Reference

## Log Source Priority

When investigating, check these sources in order of value:

1. **Authentication logs** — Who logged in, from where, when, and did they fail first?
2. **Process creation logs** — What executed? With what arguments? Parent process?
3. **Network connection logs** — What talked to what? Unusual destinations?
4. **DNS query logs** — What domains were resolved? DGA patterns?
5. **File system events** — What was created, modified, deleted?
6. **Firewall/IDS logs** — What was blocked? What triggered alerts?
7. **Application logs** — Web server access logs, database logs, custom app logs

## Common IOC Patterns

### Suspicious Process Execution
```
# Look for these patterns in process creation logs:
- powershell.exe -enc [base64]          # Encoded PowerShell — almost always malicious
- cmd.exe /c whoami                      # Reconnaissance
- certutil -urlcache -split -f http://   # File download via certutil (LOLBin)
- bitsadmin /transfer                    # File download via BITS
- mshta http://                          # Script execution via mshta
- regsvr32 /s /n /u /i:http://          # Squiblydoo — COM scriptlet execution
- rundll32 javascript:                   # Script execution via rundll32
- wmic process call create               # Remote process creation
- schtasks /create                       # Persistence via scheduled task
- net user [username] /add               # Account creation
```

### Suspicious Network Patterns
```
# DNS
- High volume of DNS queries to a single domain (tunneling)
- Queries for very long subdomains (>50 chars) — data exfil via DNS
- Queries to recently registered domains (< 30 days old)
- NXDomain spikes (DGA activity)

# Network flows
- Beaconing: Regular interval connections (every 60s, 300s, etc.) with jitter
- Large outbound transfers to unusual destinations
- Connections to known-bad IPs/domains (check threat intel feeds)
- Internal host scanning (one host connecting to many internal IPs on same port)
- RDP/SSH from unexpected sources
- SMB traffic between workstations (lateral movement indicator)
```

### Suspicious File Activity
```
# Ransomware indicators
- Mass file renames with new extensions (.encrypted, .locked, random extensions)
- Ransom notes appearing (README.txt, DECRYPT_FILES.html, etc.)
- Shadow copy deletion (vssadmin delete shadows)

# Webshells
- New files in web server directories (especially .php, .aspx, .jsp)
- Files with base64_decode, eval(), exec() in web-accessible paths
- Recent modification of existing web files

# Persistence
- New files in startup directories
- Modified registry run keys
- New scheduled tasks or cron jobs
- New systemd services
```

## Windows Event Log Quick Reference

| Event ID | Log | What It Means |
|----------|-----|--------------|
| 4624 | Security | Successful logon |
| 4625 | Security | Failed logon |
| 4648 | Security | Explicit credential logon (runas) |
| 4672 | Security | Special privileges assigned (admin logon) |
| 4688 | Security | Process creation (enable command line auditing!) |
| 4698 | Security | Scheduled task created |
| 4720 | Security | User account created |
| 4732 | Security | Member added to local group |
| 7045 | System | New service installed |
| 1102 | Security | Audit log cleared (this itself is suspicious) |
| 4697 | Security | Service installed |
| 4663 | Security | Access attempt on object (file auditing) |
| 1 | Sysmon | Process creation with hashes and parent process |
| 3 | Sysmon | Network connection |
| 7 | Sysmon | Image loaded (DLL) |
| 8 | Sysmon | CreateRemoteThread (injection indicator) |
| 10 | Sysmon | Process access (credential dumping indicator) |
| 11 | Sysmon | File creation |
| 13 | Sysmon | Registry value set |
| 22 | Sysmon | DNS query |

## Linux Log Quick Reference

| Log File | What It Contains |
|----------|-----------------|
| /var/log/auth.log (Debian) or /var/log/secure (RHEL) | Authentication events, sudo usage, SSH |
| /var/log/syslog or /var/log/messages | General system events |
| /var/log/kern.log | Kernel events |
| /var/log/cron.log or journalctl -u cron | Cron job execution |
| /var/log/apache2/ or /var/log/nginx/ | Web server access and error logs |
| /var/log/audit/audit.log | auditd events (if configured) |
| journalctl | systemd journal (all services) |

## Analysis Commands

```bash
# Linux — Quick threat hunting
# Failed SSH logins
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn | head 20

# Successful logins from unusual sources
grep "Accepted" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn

# Recently modified files in sensitive directories
find /etc /usr/bin /usr/sbin -mtime -7 -type f 2>/dev/null

# Unusual SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Listening services
ss -tulnp

# Active connections to external IPs
ss -tupn | grep -v '127.0.0.1\|::1'

# Cron jobs for all users
for user in $(cut -f1 -d: /etc/passwd); do echo "--- $user ---"; crontab -u $user -l 2>/dev/null; done

# Check for webshells
find /var/www -name "*.php" -mtime -30 -exec grep -l "eval\|base64_decode\|system\|exec\|passthru" {} \;
```

```powershell
# Windows — Quick threat hunting
# Failed logons (last 24 hours)
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=(Get-Date).AddDays(-1)} |
  Group-Object {$_.Properties[5].Value} | Sort Count -Descending

# New services installed
Get-WinEvent -FilterHashtable @{LogName='System';Id=7045;StartTime=(Get-Date).AddDays(-7)}

# Scheduled tasks created
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4698;StartTime=(Get-Date).AddDays(-7)}

# PowerShell script block logging
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} -MaxEvents 100

# Unusual processes
Get-Process | Where-Object {$_.Path -notlike "C:\Windows\*" -and $_.Path -notlike "C:\Program Files*"} |
  Select Name, Path, Id
```

## SIEM Query Templates

Provide detection queries in Sigma format first (portable), then translate to the user's SIEM if known:
- Splunk SPL
- Elastic/Kibana KQL
- Microsoft Sentinel KQL
- CrowdStrike Falcon LogScale
