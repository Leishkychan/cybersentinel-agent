# System Hardening Reference

## Hardening Philosophy

Hardening is about reducing the attack surface. The goal: make the system do exactly what it needs to do, and nothing else. Every unnecessary service, open port, default credential, and excessive permission is an opportunity for an attacker.

## Linux Hardening Checklist

### Authentication & Access
- [ ] Disable root SSH login (`PermitRootLogin no` in sshd_config)
- [ ] Enforce key-based SSH authentication (`PasswordAuthentication no`)
- [ ] Configure SSH on non-standard port (defense in depth, not security)
- [ ] Implement fail2ban or similar for brute force protection
- [ ] Set strong password policy (pam_pwquality)
- [ ] Configure account lockout after failed attempts
- [ ] Audit sudoers — minimize NOPASSWD entries
- [ ] Remove or lock unnecessary user accounts
- [ ] Implement MFA for SSH (e.g., Google Authenticator PAM module)

### Network
- [ ] Enable firewall (iptables/nftables/ufw) — default deny inbound
- [ ] Disable IPv6 if not needed
- [ ] Disable unused network services
- [ ] Configure TCP wrappers (/etc/hosts.allow, /etc/hosts.deny)
- [ ] Enable SYN cookies (`net.ipv4.tcp_syncookies = 1`)
- [ ] Disable IP forwarding if not a router (`net.ipv4.ip_forward = 0`)
- [ ] Disable ICMP redirects
- [ ] Enable reverse path filtering (`net.ipv4.conf.all.rp_filter = 1`)

### File System
- [ ] Set noexec,nosuid,nodev on /tmp, /var/tmp, /dev/shm
- [ ] Enable file integrity monitoring (AIDE, Tripwire, OSSEC)
- [ ] Restrict /etc/cron permissions
- [ ] Set umask 027 or 077
- [ ] Audit SUID/SGID binaries — remove unnecessary ones
- [ ] Enable audit logging (auditd)
- [ ] Restrict core dumps

### Patching & Software
- [ ] Enable automatic security updates (unattended-upgrades)
- [ ] Remove unnecessary packages
- [ ] Disable unused services (`systemctl disable [service]`)
- [ ] Pin package versions for critical services

### Logging & Monitoring
- [ ] Configure centralized log forwarding (rsyslog/syslog-ng to SIEM)
- [ ] Enable auditd with rules for: file access, privilege escalation, account changes
- [ ] Install and configure Sysmon for Linux (if available) or equivalent
- [ ] Monitor for unauthorized cron jobs
- [ ] Set up log rotation to prevent disk exhaustion attacks

## Windows Hardening Checklist

### Authentication & Access
- [ ] Disable local Administrator account (or rename + strong password)
- [ ] Implement LAPS (Local Administrator Password Solution)
- [ ] Enforce MFA for all remote access
- [ ] Configure account lockout policies (10 attempts, 30 min lockout)
- [ ] Implement tiered administration (T0/T1/T2)
- [ ] Disable NTLM where possible, enforce Kerberos
- [ ] Enable Credential Guard
- [ ] Configure Protected Users security group for privileged accounts

### Network
- [ ] Enable Windows Firewall on all profiles (Domain, Private, Public)
- [ ] Disable SMBv1 (`Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol`)
- [ ] Enable SMB signing
- [ ] Disable LLMNR (`HKLM\Software\Policies\Microsoft\Windows NT\DNSClient` EnableMulticast=0)
- [ ] Disable NetBIOS over TCP/IP
- [ ] Disable WPAD if not needed
- [ ] Configure Windows Defender Firewall logging

### Execution Control
- [ ] Enable AppLocker or Windows Defender Application Control (WDAC)
- [ ] Block execution from user-writable directories
- [ ] Disable Windows Script Host if not needed
- [ ] Enable Attack Surface Reduction (ASR) rules
- [ ] Disable Office macros via Group Policy (or limit to signed only)
- [ ] Enable PowerShell Constrained Language Mode for non-admins

### Logging & Monitoring
- [ ] Enable PowerShell Script Block Logging
- [ ] Enable PowerShell Module Logging
- [ ] Enable command-line process auditing (Event ID 4688)
- [ ] Deploy Sysmon with a strong configuration (SwiftOnSecurity or Olaf Hartong)
- [ ] Forward logs to SIEM
- [ ] Enable Windows Defender real-time protection + cloud-delivered protection
- [ ] Monitor for Event ID 1102 (log clearing)

## Cloud Hardening (AWS/Azure/GCP)

### Identity & Access
- [ ] Enforce MFA on all accounts, especially root/global admin
- [ ] Implement least-privilege IAM policies
- [ ] Use temporary credentials (IAM roles, service accounts) not long-lived keys
- [ ] Rotate access keys regularly
- [ ] Enable CloudTrail/Azure Monitor/GCP Audit Logs
- [ ] Disable unused regions (AWS)

### Network
- [ ] Use VPCs/VNets with private subnets for internal services
- [ ] Security groups: default deny, explicit allow by port and source
- [ ] No 0.0.0.0/0 inbound rules except on load balancers/CDN
- [ ] Enable VPC Flow Logs
- [ ] Use PrivateLink/Private Endpoints for service access

### Storage
- [ ] Enable encryption at rest (default KMS or customer-managed keys)
- [ ] Enable encryption in transit (TLS everywhere)
- [ ] Block public access on S3 buckets/storage accounts (account-level setting)
- [ ] Enable versioning and MFA delete on critical storage
- [ ] Audit storage access policies regularly

### Monitoring
- [ ] Enable GuardDuty (AWS) / Defender for Cloud (Azure) / Security Command Center (GCP)
- [ ] Configure billing alerts (cryptomining detection)
- [ ] Set up CloudWatch/Azure Monitor alerts for suspicious API calls
- [ ] Enable Config Rules / Azure Policy for compliance drift detection

## CIS Benchmark Mapping

When the user needs compliance-oriented hardening, map recommendations to CIS Benchmark sections. CIS benchmarks are organized by:
1. Initial Setup (filesystem, updates, boot settings)
2. Services (remove unnecessary services)
3. Network Configuration
4. Logging and Auditing
5. Access, Authentication, and Authorization
6. System Maintenance

Reference the specific CIS benchmark version for the OS/platform being hardened. Recommendations should include the CIS control number for traceability.

## Verification

After hardening, verify with:
- CIS-CAT assessment tool (automated CIS benchmark scanning)
- Lynis (Linux security auditing)
- OpenSCAP (SCAP compliance checking)
- Microsoft Security Compliance Toolkit (Windows)
- Prowler (AWS), ScoutSuite (multi-cloud)
- Manual spot-checks of critical settings
