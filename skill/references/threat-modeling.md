# Threat Modeling Reference

## When to Threat Model

Threat model whenever the user is:
- Designing a new system or feature
- Evaluating an existing architecture for security
- Preparing for a security review or audit
- Planning infrastructure changes
- Assessing a third-party integration

## STRIDE Framework

The primary framework. Each letter represents a category of threat:

| Threat | Property Violated | Question to Ask |
|--------|------------------|-----------------|
| **S**poofing | Authentication | Can someone pretend to be someone/something else? |
| **T**ampering | Integrity | Can someone modify data they shouldn't? |
| **R**epudiation | Non-repudiation | Can someone deny they performed an action? |
| **I**nformation Disclosure | Confidentiality | Can someone access data they shouldn't? |
| **D**enial of Service | Availability | Can someone prevent legitimate use? |
| **E**levation of Privilege | Authorization | Can someone do things they're not allowed to? |

### Applying STRIDE

For each component in the system:
1. Draw or describe the data flow (what talks to what, over what channel, carrying what data)
2. For each data flow crossing a trust boundary, ask all 6 STRIDE questions
3. For each identified threat, assess likelihood and impact
4. Map to MITRE ATT&CK techniques where applicable
5. Define mitigations

## PASTA (Process for Attack Simulation and Threat Analysis)

Seven-stage risk-centric framework:

1. **Define Objectives** — What are the business requirements? What's the risk appetite?
2. **Define Technical Scope** — Architecture, technologies, dependencies, data flows
3. **Application Decomposition** — Break down the system into components, identify trust boundaries, entry/exit points
4. **Threat Analysis** — What threat actors are relevant? What are their capabilities and motivations?
5. **Vulnerability Analysis** — What weaknesses exist? Map to CVEs and CWEs
6. **Attack Modeling** — Build attack trees showing how an adversary could chain vulnerabilities
7. **Risk & Impact Analysis** — Quantify risk, prioritize remediation, map to business impact

## Attack Trees

Use attack trees to model complex attack paths:

```
Goal: Compromise Customer Database
├── Path 1: SQL Injection via Web App
│   ├── Find injectable parameter
│   ├── Bypass WAF
│   └── Extract data
├── Path 2: Compromised Credentials
│   ├── Phishing admin user
│   │   ├── Spearphishing email
│   │   └── MFA bypass (SIM swap, fatigue)
│   └── Use stolen creds to access DB
├── Path 3: Supply Chain Attack
│   ├── Compromise third-party library
│   └── Inject backdoor into dependency
└── Path 4: Insider Threat
    ├── Malicious DBA
    └── Compromised developer laptop
```

For each leaf node, assess:
- Feasibility (skill required, tools needed, time)
- Likelihood (is this attack common in the wild?)
- Impact (what does the attacker gain?)
- Existing controls (what's already preventing this?)
- Gaps (what's missing?)

## Trust Boundaries

Critical concept. A trust boundary exists wherever:
- Data crosses between different privilege levels
- Communication moves between different networks
- A request moves between different organizational domains
- User input enters the system

Common trust boundaries:
- Internet ↔ DMZ
- DMZ ↔ Internal network
- Client ↔ Server
- Application ↔ Database
- User process ↔ Kernel
- Container ↔ Host
- Third-party service ↔ Your infrastructure

Every crossing of a trust boundary needs: authentication, authorization, input validation, encryption in transit, and logging.

## Data Flow Diagram Elements

When building or reviewing a DFD for threat modeling:

| Element | Symbol | Security Questions |
|---------|--------|--------------------|
| External Entity | Rectangle | Who are they? How are they authenticated? |
| Process | Circle | What does it do? What permissions does it have? |
| Data Store | Parallel lines | What's stored? How is it encrypted? Who has access? |
| Data Flow | Arrow | What protocol? Is it encrypted? Is it authenticated? |
| Trust Boundary | Dashed line | What changes at this boundary? |

## Output Format for Threat Models

```
## Threat Model: [System Name]

### Scope
[What's included and excluded]

### Architecture Summary
[Brief description + DFD reference]

### Assets
[What are we protecting? Ranked by criticality]

### Threat Actors
[Who might attack this? What are their capabilities?]

### Findings

#### [THREAT-001] [Name]
- **STRIDE Category**: [S/T/R/I/D/E]
- **Component**: [Affected component]
- **Attack Path**: [How the attack works]
- **ATT&CK Mapping**: [Technique ID]
- **Likelihood**: [Low/Medium/High]
- **Impact**: [Low/Medium/High]
- **Risk**: [Likelihood × Impact]
- **Existing Controls**: [What's already in place]
- **Recommended Mitigations**: [What to add]
- **Verification**: [How to test the mitigation works]
```
