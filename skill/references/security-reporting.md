# Security Reporting Reference

## Audience-Adapted Reporting

Security findings are useless if the audience can't act on them. Always determine the audience first.

### For Security Professionals
- Full technical detail — CVE IDs, CVSS vectors, affected versions, exploit references
- Verification commands and detection rules
- ATT&CK mappings with technique IDs
- Sigma/YARA/Suricata rules
- Raw evidence and IOCs

### For IT Operations / System Administrators
- What needs to be done (patched, configured, monitored)
- Specific commands and procedures
- Change management considerations
- Testing/validation steps after remediation
- Rollback plan if fix causes issues

### For Executives / Board
- Business risk language, not technical jargon
- Impact in terms of: financial loss, regulatory fines, reputational damage, operational disruption
- Risk matrix (likelihood × impact) with color coding
- Cost of remediation vs cost of incident
- Comparison to industry benchmarks
- Clear ask: budget, timeline, decision needed

### For Compliance / Auditors
- Map every finding to the applicable framework controls
- Evidence of compliance or non-compliance
- Gap analysis against the target framework
- Remediation plan with timelines
- Evidence requirements for closure

## Risk Matrix

Use this standard 5×5 matrix:

```
Impact →        Minimal    Minor    Moderate    Major    Severe
Likelihood ↓
Almost Certain   Medium     High     High       Crit     Crit
Likely           Medium     Medium   High       High     Crit
Possible         Low        Medium   Medium     High     High
Unlikely         Low        Low      Medium     Medium   High
Rare             Low        Low      Low        Medium   Medium
```

- **Critical**: Immediate action required. Escalate to leadership.
- **High**: Remediate within defined SLA. Track actively.
- **Medium**: Schedule remediation. Monitor for changes.
- **Low**: Accept risk or remediate during maintenance windows.

## Report Templates

### Vulnerability Assessment Report
```
# Vulnerability Assessment Report
**Date**: [Date]
**Scope**: [Systems/networks assessed]
**Methodology**: [Tools used, assessment type]
**Classification**: [Confidential/Internal]

## Executive Summary
[2-3 sentences: what was tested, critical findings count, overall risk posture]

## Key Metrics
- Total findings: [N]
- Critical: [N] | High: [N] | Medium: [N] | Low: [N] | Info: [N]
- Mean time to remediate (historical): [N days]
- Findings with active exploitation in the wild: [N]

## Critical & High Findings Summary
[Table: Finding, Severity, Affected Systems, Remediation, SLA]

## Detailed Findings
[Use the CVE finding template from cve-assessment.md for each finding]

## Recommendations (Prioritized)
[Ordered list by risk, grouping related fixes]

## Appendix
- Full finding details
- Scan configuration
- Excluded systems and rationale
```

### Incident Report
```
# Incident Report: [Incident Name]
**Incident ID**: [ID]
**Severity**: [P0-P4]
**Status**: [Active/Contained/Eradicated/Recovered/Closed]
**Date Detected**: [Date/Time UTC]
**Date Contained**: [Date/Time UTC]

## Executive Summary
[What happened, what's the impact, what's the current status]

## Timeline
[Chronological events — detection through current state]

## Impact Assessment
- Systems affected: [List]
- Data at risk: [Type, volume, sensitivity]
- Business impact: [Operational, financial, regulatory]
- Users/customers affected: [Scope]

## Root Cause
[What vulnerability or failure enabled this]

## ATT&CK Mapping
[Full kill chain mapping of the adversary's activity]

## Response Actions Taken
[What was done to contain, eradicate, and recover]

## Lessons Learned
[What worked, what didn't, what changes are needed]

## Recommendations
[Preventive measures to stop recurrence]
```

## Framework Mapping Quick Reference

| Finding Type | NIST CSF | ISO 27001 | CIS Controls |
|-------------|----------|-----------|-------------|
| Missing patches | PR.IP-12 | A.12.6.1 | CIS 7 |
| Weak authentication | PR.AC-1 | A.9.4.2 | CIS 6 |
| No encryption in transit | PR.DS-2 | A.10.1.1 | CIS 3 |
| Insufficient logging | DE.AE-3 | A.12.4.1 | CIS 8 |
| No incident response plan | RS.RP-1 | A.16.1.1 | CIS 17 |
| Missing network segmentation | PR.AC-5 | A.13.1.3 | CIS 12 |
| No backup/recovery | PR.IP-4 | A.12.3.1 | CIS 11 |
| Default credentials | PR.AC-1 | A.9.4.3 | CIS 5 |
