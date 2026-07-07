# Audit Report Template — Spring Boot Integration Auditor

> Part of the `spring-boot-integration-auditor` skill — back to [SKILL.md](../SKILL.md)

Copy this template and fill in every section. Do not skip any section. Use findings IDs `[H-NNN]` consistently throughout.

---

```markdown
# AUDIT REPORT — [Integration name]

**Stack:** Spring Boot [version] · Java [version] · [Maven/Gradle]
**Repository:** [absolute path or URL]
**Branch / commit:** [branch name] / [commit SHA]
**Date:** [YYYY-MM-DD]
**Auditor:** [name / tool / agent]
**Criticality:** [Critical | High | Medium | Low]
**Scope:** [Full | OWASP | 800-82 | CSF | Quick]
**Frameworks applied:** [list]

---

## 1. Executive Summary

[3-5 lines: what was audited, top findings, overall risk posture, immediate action required]

Example:
> The integration `scada-bridge` (Spring Boot 3.2.4, Java 21) was audited across the
> three frameworks. It connects to OPC UA servers and a HiveMQ broker for OT telemetry.
> Five critical findings: actuator endpoints exposed on the same port as the public API,
> a hardcoded `withDefaultPasswordEncoder()` call, a SnakeYAML 1.x deserialization,
> plain MQTT connection (port 1883, no TLS), and a `@PreAuthorize` gap allowing IDOR on
> plant tag reads. The integration **must not go to production** until critical findings
> are remediated.

---

## 2. Compliance Scorecard

| Framework | Compliant | Partial | Non-compliant | N/A | % Compliant |
|-----------|-----------|---------|---------------|-----|-------------|
| NIST SP 800-82 | n | n | n | n | XX% |
| OWASP Top 10 2021 | n/m | n/m | n/m | n/m | XX% |
| NIST CSF 2.0 | n | n | n | n | XX% |
| **TOTAL** | | | | | |

Where for OWASP: n/m = compliant categories / total applicable categories.

| Severity | Count |
|----------|-------|
| Critical | n |
| High | n |
| Medium | n |
| Low | n |
| **TOTAL findings** | n |

---

## 3. Findings

### 3.1 Critical findings (remediate within 24h)

> Each finding follows the same format. Replace the example below with real content.

#### [H-001] Actuator endpoints exposed on public port with `*` exposure

- **Framework:** NIST SP 800-82 | OWASP | CSF
- **Control/Category:** CM-6, CM-7 / A05:2021 / PR.PS-01
- **Severity:** Critical
- **File:** `src/main/resources/application.yml:12`
- **Evidence:**
  ```yaml
  management:
    endpoints:
      web:
        exposure:
          include: "*"
    server:
      port: 8080
  ```
- **Risk:** All actuator endpoints (including `/env`, `/heapdump`, `/beans`, `/configprops`) are reachable from the same port as the public REST API. `/env` exposes plaintext secrets (DB password, JWT key). `/heapdump` exposes a memory dump containing credentials from the heap. Attacker who reaches `/actuator/env` obtains full takeover.
- **Remediation:**
  ```yaml
  management:
    server:
      port: 9090
      address: 127.0.0.1
    endpoints:
      web:
        exposure:
          include: health, info, prometheus
    endpoint:
      env:
        enabled: false
      heapdump:
        enabled: false
      beans:
        enabled: false
      configprops:
        enabled: false
  ```
  And expose `9090` only via reverse proxy with mTLS / IP allowlist.
- **Validation:**
  ```bash
  curl -i http://localhost:8080/actuator/env    # must return 404
  curl -i http://localhost:9090/actuator/env    # must return 401 (or 403)
  ```

#### [H-002] [Next critical finding title]

- **Framework:** ...
- **Control/Category:** ...
- **Severity:** Critical
- **File:** ...
- **Evidence:** (snippet)
- **Risk:** ...
- **Remediation:** (snippet)
- **Validation:** ...

### 3.2 High findings (remediate within 72h)

#### [H-006] [First high finding title]

[same format]

### 3.3 Medium findings (remediate within 30 days)

#### [H-015] [First medium finding title]

[same format, more concise]

### 3.4 Low findings (remediate within 90 days)

- **[H-020]** [short title] — `file:line` — one-line fix
- **[H-021]** [short title] — `file:line` — one-line fix
- ...

---

## 4. Framework Compliance Tables

### 4.1 NIST SP 800-82

| Control | Description | Status | Evidence |
|---------|-------------|--------|----------|
| AC-3 | Access enforcement | Compliant / Partial / Non-compliant / N/A | `file:line` or `MISSING` |
| AC-4 | Information flow enforcement | ... | ... |
| AC-6 | Least privilege | ... | ... |
| AU-2 | Audit events | ... | ... |
| AU-3 | Content of audit records | ... | ... |
| AU-6 | Audit review | ... | ... |
| CM-6 | Configuration settings | ... | ... |
| CM-7 | Least functionality | ... | ... |
| IA-2 | User identification | ... | ... |
| IA-5 | Authenticator management | ... | ... |
| IR-4 | Incident handling | ... | ... |
| SC-7 | Boundary protection | ... | ... |
| SC-8 | Transmission confidentiality | ... | ... |
| SC-13 | Cryptographic protection | ... | ... |
| SC-28 | Protection of info at rest | ... | ... |
| SI-2 | Flaw remediation | ... | ... |
| SI-4 | System monitoring | ... | ... |
| SI-7 | Software integrity | ... | ... |
| SI-10 | Input validation | ... | ... |
| SR-3 | Supply chain controls | ... | ... |
| SR-4 | Provenance | ... | ... |
| SR-11 | Component authenticity | ... | ... |

(For OT integrations, add OPC UA / MQTT / Modbus protocol checks as separate rows.)

### 4.2 OWASP Top 10 (2021)

| Category | Status | Findings | Notes |
|----------|--------|----------|-------|
| A01:2021 Broken Access Control | Compliant/Partial/Non-compliant/N/A | [H-NNN, ...] | |
| A02:2021 Cryptographic Failures | ... | ... | |
| A03:2021 Injection | ... | ... | |
| A04:2021 Insecure Design | ... | ... | |
| A05:2021 Security Misconfiguration | ... | ... | |
| A06:2021 Vulnerable Components | ... | ... | |
| A07:2021 Auth Failures | ... | ... | |
| A08:2021 Data Integrity Failures | ... | ... | |
| A09:2021 Logging Failures | ... | ... | |
| A10:2021 SSRF | ... | ... | |

### 4.3 NIST CSF 2.0 Maturity

| Function | Compliant | Partial | Non-compliant | N/A | % |
|----------|-----------|---------|---------------|-----|---|
| Govern (GV) | n | n | n | n | XX% |
| Identify (ID) | n | n | n | n | XX% |
| Protect (PR) | n | n | n | n | XX% |
| Detect (DE) | n | n | n | n | XX% |
| Respond (RS) | n | n | n | n | XX% |
| Recover (RC) | n | n | n | n | XX% |
| **TOTAL** | | | | | XX% |

#### Per-category detail (sample, fill all applicable)

| Sub-category | Status | Evidence |
|--------------|--------|----------|
| GV.OC-01 | ... | ... |
| GV.RR-01 | ... | ... |
| ID.AM-02 | ... | ... |
| PR.AA-01 | ... | ... |
| ... | ... | ... |

---

## 5. Remediation Plan

### 5.1 Critical (24h SLA)

1. [H-001] Restrict actuator endpoints — Owner: backend lead
2. [H-002] Replace SnakeYAML 1.x with SafeConstructor on 2.x — Owner: dev
3. ...

### 5.2 High (72h SLA)

1. [H-006] Add @PreAuthorize to plant tag endpoints — Owner: dev
2. [H-007] Switch MQTT to mTLS — Owner: OT team
3. ...

### 5.3 Medium (30 days, grouped by category)

- **Authentication (3 findings)**: implement MFA, lockout, audit
- **Cryptography (2 findings)**: upgrade TLS ciphers, rotate keys
- **Dependencies (4 findings)**: bump log4j 2.17+, snakeyaml 2.x, jackson 2.15+
- ...

### 5.4 Low (90 days, list)

- [H-020] Add banner-mode=off
- [H-021] Document `/internal/forensic-snapshot` endpoint
- ...

---

## 6. Operational Impact Assessment (if Criticality >= High)

| Aspect | Current state | Impact if exploited |
|--------|---------------|---------------------|
| Production continuity | Compromise of OT write endpoint | Setpoint manipulation, possible plant shutdown |
| Safety | PLC write capability | Unsafe setpoint risk to personnel |
| Data confidentiality | Heap dump leak | All secrets exposed |
| Compliance | Multiple non-compliant controls | Fails ISO 27001 / NIS2 audit |
| Reputational | OT incident | Loss of customer trust, regulatory fines |

---

## 7. Re-audit Cadence

| Trigger | When |
|---------|------|
| Critical finding remediation | Within 7 days of fix |
| New release / deployment | Before each prod deploy |
| Dependency CVE > High | Within patch SLA |
| Major refactor | Re-audit affected modules |
| Annual | Full audit |

---

## 8. Appendix: Commands Executed

List of commands run during the audit, with their output (truncated if large).

```bash
# Phase A - Reconnaissance
$ ls src/main/java/
controller/  service/  repository/  config/  model/

$ cat pom.xml | grep -A1 spring-boot.version
<spring-boot.version>3.2.4</spring-boot.version>

# Phase B - Static scanning
$ mvn org.owasp:dependency-check-maven:check -DfailBuildOnCVSS=7
... (truncated) ...
[CRITICAL] CVE-2021-44228 log4j-core 2.14.1 -> 2.17.1+
[HIGH]     CVE-2022-1471 snakeyaml 1.30 -> 2.0+
...

$ rg -n "withDefaultPasswordEncoder" src/ --type java
src/main/java/com/example/config/SecurityConfig.java:34
        return User.withDefaultPasswordEncoder()
        ...

$ rg -n "Runtime\.getRuntime\(\)\.exec" src/ --type java
src/main/java/com/example/ot/PingService.java:22
        Runtime.getRuntime().exec("ping -c 1 " + host)
        ...
```

---

## 9. Sign-off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Auditor | | | |
| Tech lead | | | |
| Security lead | | | |
| OT lead (if applicable) | | | |
| CISO (if critical) | | | |

---

## Notes

- This report is **confidential** and should be shared only with stakeholders identified in `GV.OC-02`.
- Track all findings in the central issue tracker with the labels `security`, `audit`, and the corresponding framework.
- Do not delete the audit even after remediation: required for compliance evidence.
- For re-audits, reference the previous report ID and note the delta.
```

---

## Usage Notes

1. **Replacing placeholders**: every `[BRACKETED VALUE]` must be replaced. No placeholder may remain.
2. **Finding IDs**: number sequentially `H-001` ... `H-NNN`. Do not reuse IDs across reports.
3. **Severity**: do not change. Use the matrix in SKILL.md.
4. **Evidence**: must be copy-paste from the real source. No paraphrasing.
5. **Remediation**: must be a working snippet. Test it before publishing the report.
6. **Validation**: must be a runnable command that confirms the fix.
7. **Criticality matrix**: for OT integrations, escalate technical severity by one level if the issue affects safety or production continuity.
8. **Output language**: matches the user's request (English or Spanish).
