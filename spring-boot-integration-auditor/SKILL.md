---
name: spring-boot-integration-auditor
description: >
  Compliance auditor for Spring Boot integrations. Verifies code against
  NIST SP 800-82 (ICS/OT Security), OWASP Top 10 (2021) and NIST CSF 2.0.
  Activate when the user asks: audit, compliance, security review, pentest,
  hardening, "review security", "verify compliance", "analyze this Spring Boot",
  "review this microservice", or mentions Spring Boot + security / NIST / OWASP / CSF.
  Also for: pre-production review, vendor due-diligence, M&A technical assessment,
  regulatory audits (ISO 27001, NIS2, PCI-DSS, SOX, NERC-CIP), or inheriting legacy projects.
  Do not use for: non-Spring apps (Node, Python, .NET), pure infrastructure audits
  (network/SIEM), or active pentests without written authorization.
domain: cybersecurity
subdomain: application-security
tags:
  - spring-boot
  - java
  - nist-800-82
  - owasp-top-10
  - nist-csf
  - security-audit
  - compliance
  - ics-security
  - ot-security
  - static-analysis
  - secure-coding
version: "1.0"
author: opencode-skill
license: Apache-2.0
nist_csf:
  - GV.OC-01
  - GV.RR-01
  - ID.AM-02
  - ID.RA-01
  - PR.AC-01
  - PR.DS-01
  - DE.CM-01
  - RS.AN-03
  - RS.MI-01
  - RC.RP-01
mitre_attack:
  - T1190
  - T1078
  - T1059
  - T1530
owasp_top_10:
  - A01:2021
  - A02:2021
  - A03:2021
  - A04:2021
  - A05:2021
  - A06:2021
  - A07:2021
  - A08:2021
  - A09:2021
  - A10:2021
---

# Spring Boot Integration Auditor

Security audit skill for Spring Boot integrations. Covers the 3 frameworks (NIST 800-82 + OWASP Top 10 + NIST CSF 2.0) with checks specific to the enterprise Java stack (Spring Boot 3.x, Spring Security 6.x, JPA, Actuator, OT/ICS integrations via Eclipse Milo, MQTT, Modbus, OPC UA).

## When to Use

- Audit a Spring Boot microservice or integration before going to production
- Verify compliance for external audit (ISO 27001, NIS2, PCI-DSS, SOX, NERC-CIP)
- Hardening a legacy application that is being modernized
- Technical due-diligence of a vendor delivering Spring software
- Investigate an incident where the application is suspected as the attack vector
- M&A: risk assessment of inherited code

**Do not use** for:
- Non-Spring applications (Node, Python, .NET, Go) -> use stack-specific skills
- Pure infrastructure audits (network, SIEM, EDR) -> use `auditing-*-infrastructure`
- Active pentest without written authorization from the owner
- Performance/architecture reviews (not security)

## Prerequisites

Before invoking this skill, ensure:

- The target repository path exists and is accessible
- The project contains `pom.xml` or `build.gradle` with `spring-boot-starter-*`
- If SCA tools are required, verify: `mvn --version`, `dependency-check` (OWASP), optional `gitleaks`, `trivy`, `snyk`
- Java 17+ available if you want to run the application
- Read permissions over all source code (nothing is modified)

## Skill Structure

```
spring-boot-integration-auditor/
├── SKILL.md                              <- This file (orchestrator)
├── logic/
│   └── triage.md                         <- Triage: scope + criticality
├── references/
│   ├── owasp-top-10.md                   <- Checks A01-A10 with Spring patterns
│   ├── nist-800-82.md                    <- ICS controls mapped to Spring Boot
│   ├── nist-csf-2.0.md                   <- Functions GV/ID/PR/DE/RS/RC
│   ├── spring-boot-patterns.md           <- Vulnerable vs hardened snippets
│   └── report-template.md                <- Final report template
```

## Execution Flow

Each activation follows this order. Do not skip steps.

### 1. Triage

Load `logic/triage.md`. Determine (max 3 questions, one at a time):

| Question | Options |
|----------|---------|
| Which integration to audit? | Path to Spring Boot repo |
| What is the operational criticality? | Critical (OT/ICS) / High (core) / Medium (support) / Low (admin) |
| What scope do you need? | Full / OWASP / 800-82 / CSF / Quick |

If the user already gave full context, skip triage and execute directly.

### 2. Load references (per scope)

Per scope, load ONLY the necessary references to avoid context bloat:

| Scope | References to load |
|-------|-------------------|
| Full | owasp-top-10 + nist-800-82 + nist-csf-2.0 + spring-boot-patterns |
| OWASP only | owasp-top-10 + spring-boot-patterns |
| 800-82 only | nist-800-82 + spring-boot-patterns |
| CSF only | nist-csf-2.0 |
| Quick | owasp-top-10 (A01-A10 summary) |

### 3. Reconnaissance (Phase A — non-destructive)

Identify the project without modifying anything:

```bash
# Project structure
ls src/main/java/ -R 2>/dev/null || dir /s /b src\main\java\
ls src/main/resources/ -R 2>/dev/null || dir /s /b src\main\resources\

# Stack detection
cat pom.xml 2>/dev/null || cat build.gradle 2>/dev/null
cat src/main/resources/application.yml 2>/dev/null || cat src/main/resources/application.properties 2>/dev/null

# Exposed endpoints
rg -n "@(RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)" src/ --type java

# Security configuration
rg -n "@PreAuthorize|@Secured|hasRole|hasAuthority|permitAll|denyAll" src/ --type java
rg -n "SecurityFilterChain|@EnableWebSecurity|@EnableMethodSecurity" src/ --type java
```

### 4. Static Scanning (Phase B)

Run the available tools. If not installed, use grep/ripgrep equivalents.

```bash
# OWASP Dependency Check (if Maven + plugin available)
mvn org.owasp:dependency-check-maven:check -DfailBuildOnCVSS=7 -q 2>&1 | tail -50

# Secret scanning
gitleaks detect --source . --no-banner 2>&1 | head -50

# Fallback: grep for common secrets
rg -in "(password|api[_-]?key|secret|token)\s*=\s*[\"'][^\"']{8,}" src/ --type java

# Actuator endpoints
rg -n "management\.endpoints\.web\.exposure" src/main/resources/

# Insecure deserialization
rg -n "(ObjectInputStream|XMLDecoder|XStream|SnakeYaml|Yaml\(\)\.load)" src/ --type java

# SQL injection candidates
rg -in "(createQuery|createNativeQuery|nativeQuery).*\\+|@Query.*\\+" src/ --type java

# Command injection
rg -n "Runtime\.getRuntime\(\)\.exec|ProcessBuilder" src/ --type java
```

### 5. Framework review (Phases C, D, E)

For each framework, use the corresponding reference and map each finding with:
- File + exact line
- Control ID / OWASP category / CSF subcategory
- Severity (CVSS if applicable)
- Vulnerable snippet + secure snippet
- Remediation validation

See `references/owasp-top-10.md`, `references/nist-800-82.md`, `references/nist-csf-2.0.md`.

### 6. Generate report

Use `references/report-template.md` as the skeleton. The report MUST include:

1. Executive summary (3-5 lines)
2. Compliance scorecard table (% and severity count per framework)
3. Detailed findings (sorted by severity)
4. Framework compliance tables
5. Prioritized remediation plan (24h / 72h / 30d / 90d)
6. Appendix with commands executed and their output

### 7. Delivery

- If the user requests, write the report to `[project directory]/audit-report-[YYYY-MM-DD].md`
- Otherwise, deliver the report in the conversation

## Severity Classification

Severity is NOT only CVSS. Also evaluate operational impact per criticality:

| Severity | Technical criteria | Operational criteria (per Criticality) |
|----------|-------------------|----------------------------------------|
| **Critical** | CVSS >= 9.0, RCE, auth bypass, prod secret exposure | Can stop production, compromise physical safety, expose OT data |
| **High** | CVSS 7.0-8.9, injection, broken access control, SSRF | Unauthorized access to core systems, production data exposure |
| **Medium** | CVSS 4.0-6.9, misconfig, vulnerable deps without known exploit | Insufficient hardening, incomplete logging on non-critical endpoints |
| **Low** | CVSS < 4.0, documentation, optimization | Recommended improvement, suboptimal config without immediate risk |

## Rules of Engagement

1. **Non-destructive**: never modify code, configs, or run the app during the audit
2. **Mandatory evidence**: every finding must include file:line + exact snippet
3. **No false positives**: if unsure, mark as "requires manual verification"
4. **One step at a time**: do not bombard the user with multiple questions
5. **Stack detection first**: if not Spring Boot, stop and inform
6. **Full scope for Critical/High**: always suggest Full scope for High/Critical criticality even if user asks for Quick
7. **Real snippets**: remediation code must be copy-pasteable and compile against Spring Boot 3.x

## Evidence Requirements (per finding)

Each finding MUST have:

```markdown
### [H-001] Descriptive title
- **Framework:** NIST SP 800-82 | OWASP | CSF
- **Control/Category:** e.g. AC-3 / A01:2021 / PR.AC-01
- **Severity:** Critical | High | Medium | Low
- **File:** `src/main/java/.../X.java:42`
- **Evidence:**
  ```java
  // exact snippet of the code found
  ```
- **Risk:** explanation of the impact
- **Remediation:**
  ```java
  // secure code
  ```
- **Validation:** [command/check to verify it is fixed]
```

DO NOT report findings without the 6 minimum fields.

## Supported Stack

| Component | Supported version | Notes |
|-----------|-------------------|-------|
| Java | 17 LTS, 21 LTS | Versions < 17 -> medium finding (EOL or near) |
| Spring Boot | 3.x (2.x EOL since Nov 2023) | Boot 2.x -> high finding in CSF PR.AC |
| Spring Security | 6.x | Lambda config (no WebSecurityConfigurerAdapter, deprecated) |
| Spring Data JPA | 3.x | Hibernate 6.x |
| Maven | 3.8+ | OWASP dependency-check plugin |
| Gradle | 7.x+ | OWASP dependency-check plugin |
| Spring Boot Actuator | 3.x | Endpoints never on /public |
| Eclipse Milo | 1.x | OPC UA client (ICS) |
| HiveMQ MQTT | 1.x | MQTT client (ICS) |
| j2mod | 3.x | Modbus client (ICS) |

## Output Format (Summary)

The report is delivered in markdown with this structure:

```
# AUDIT REPORT — [Integration name]

**Stack:** Spring Boot [version] · Java [version] · [build tool]
**Date:** [YYYY-MM-DD]
**Criticality:** [level]
**Scope:** [type]

## Executive Summary
[3-5 lines]

## Compliance Scorecard
[table per framework]

## Findings
### Critical
### High
### Medium
### Low

## Framework Compliance Tables
### NIST SP 800-82
### OWASP Top 10 2021
### NIST CSF 2.0 Maturity

## Remediation Plan
### 24h
### 72h
### 30d
### 90d

## Appendix: Commands Executed
```

Full template in `references/report-template.md`.

## References

- OWASP Top 10 2021: https://owasp.org/Top10/
- NIST SP 800-82 Rev 3: https://csrc.nist.gov/pubs/sp/800/82/r3/final
- NIST CSF 2.0: https://www.nist.gov/cyberframework
- Spring Security Reference: https://docs.spring.io/spring-security/reference/
- OWASP Dependency-Check: https://owasp.org/www-project-dependency-check/
- CVE Search: https://nvd.nist.gov/vuln/search
- Base skills repository: https://github.com/mukul975/Anthropic-Cybersecurity-Skills
