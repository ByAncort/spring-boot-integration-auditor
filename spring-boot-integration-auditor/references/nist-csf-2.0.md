# NIST Cybersecurity Framework (CSF) 2.0 — Spring Boot Maturity Assessment

> Part of the `spring-boot-integration-auditor` skill — back to [SKILL.md](../SKILL.md)

NIST CSF 2.0 (February 2024) introduces a 6th function **Govern (GV)** and expands scope from critical infrastructure to all organizations. This file maps the 22 CSF categories to Spring Boot integration maturity.

**When to use**: assess organizational/process maturity, not just code. Useful for compliance reporting, board-level risk communication, gap analysis for ISO 27001 / NIS2 / SOC 2.

---

## Framework Structure (CSF 2.0)

```
GOVERN (GV)         <- NEW: cross-cutting risk governance
  GV.OC  Organizational Context
  GV.RM  Risk Management Strategy
  GV.RR  Roles, Responsibilities, Authorities
  GV.PO  Policies, Processes, Procedures
  GV.OV  Oversight
  GV.SC  Cybersecurity Supply Chain Risk Management
  GV.SI  Situational Awareness (added 2.0)

IDENTIFY (ID)
  ID.AM  Asset Management
  ID.RA  Risk Assessment
  ID.IM  Improvement
  ID.SC  Supply Chain Risk Management (added 2.0)

PROTECT (PR)
  PR.AA  Identity, Authentication, and Access Control (renamed 2.0)
  PR.AT  Awareness and Training
  PR.DS  Data Security
  PR.PS  Platform Security
  PR.IR  Technology Infrastructure Resilience

DETECT (DE)
  DE.CM  Continuous Monitoring
  DE.AE  Anomaly and Event Analysis

RESPOND (RS)
  RS.RP  Response Planning
  RS.CO  Communications
  RS.AN  Analysis
  RS.MI  Mitigation
  RS.IM  Incident Recovery Improvements

RECOVER (RC)
  RC.RP  Recovery Planning
  RC.IM  Improvement (renamed 2.0)
  RC.CO  Communications
```

---

## Maturity Levels (per category)

| Level | Description | Evidence required |
|-------|-------------|-------------------|
| **Non-compliant** | No evidence of control | No code, no config, no doc references |
| **Partial** | Control partially implemented or with gaps | Some evidence but with weaknesses or single points of failure |
| **Compliant** | Control fully implemented and verified | Multiple layers, tested, monitored |

For sub-categories (e.g. PR.AA-01.1), use the parent category level unless specifically called out.

---

## GOVERN (GV) — Risk Governance

### GV.OC — Organizational Context

**Goal**: organization understands its role in the ecosystem, dependencies, and mission.

| Sub-cat | Spring Boot integration evidence | Maturity |
|---------|----------------------------------|----------|
| GV.OC-01 | Mission of the integration documented (e.g. CONFIDENTIAL file in repo or wiki link) | |
| GV.OC-02 | Internal stakeholders identified (in `OWNERS`, `CODEOWNERS`, `README`) | |
| GV.OC-03 | External dependencies documented (vendors, libraries, cloud providers) | |
| GV.OC-04 | Critical outcomes of the integration defined (SLAs, RTO, RPO) | |
| GV.OC-05 | OT/IT context understood (which plants, which systems) | Required for OT integrations |

### GV.RM — Risk Management Strategy

| Sub-cat | Evidence | Maturity |
|---------|----------|----------|
| GV.RM-01 | Risk management objectives for the app exist | |
| GV.RM-02 | Risk tolerance defined and approved | |
| GV.RM-03 | Risk treatment plan (this report is one input) | |
| GV.RM-04 | Risk-informed decisions documented | |

### GV.RR — Roles, Responsibilities, Authorities

```bash
# Check ownership
ls CODEOWNERS 2>/dev/null
ls OWNERS 2>/dev/null
ls SECURITY.md 2>/dev/null
```

| Sub-cat | Evidence | Maturity |
|---------|----------|----------|
| GV.RR-01 | `CODEOWNERS` file exists and is enforced in PR | |
| GV.RR-02 | Security roles defined (security champion, IR lead) | |
| GV.RR-03 | Budget / authority for security decisions allocated | |
| GV.RR-04 | Performance management includes security (review process) | |

### GV.PO — Policies, Processes, Procedures

| Sub-cat | Evidence | Maturity |
|---------|----------|----------|
| GV.PO-01 | Secure coding policy exists | |
| GV.PO-02 | SDLC process documented (how a feature goes from idea to prod) | |
| GV.PO-03 | Exception / waiver process exists | |
| GV.PO-04 | Policy version-controlled and reviewed annually | |
| GV.PO-05 | OT-specific policies (e.g. no internet from OT zone) | Required for OT |

### GV.OV — Oversight

| Sub-cat | Evidence | Maturity |
|---------|----------|----------|
| GV.OV-01 | Security KPIs defined and reviewed (e.g. patch SLA, vuln count) | |
| GV.OV-02 | Audit findings tracked to closure | |
| GV.OV-03 | Independent review of security controls (this audit counts) | |

### GV.SC — Cybersecurity Supply Chain Risk Management

```bash
# SBOM generation
rg -n "cyclonedx|spdx|sbom" pom.xml build.gradle 2>/dev/null
ls target/bom.json 2>/dev/null
```

| Sub-cat | Evidence | Maturity |
|---------|----------|----------|
| GV.SC-01 | Vendor / supplier cyber risk management process exists | |
| GV.SC-02 | Critical suppliers identified (Spring, Eclipse Milo, j2mod) | |
| GV.SC-03 | Contracts include security requirements (right to audit) | |
| GV.SC-04 | Suppliers prioritized by criticality | |
| GV.SC-05 | SLAs with suppliers include security response | |
| GV.SC-06 | SBOM maintained and reviewed per release | |
| GV.SC-07 | Supplier incidents monitored and assessed | |
| GV.SC-08 | Supplier included in incident response | |
| GV.SC-09 | Supply chain risks included in organizational risk register | |
| GV.SC-10 | Primary / alternate suppliers identified | |

### GV.SI — Situational Awareness (NEW 2.0)

| Sub-cat | Evidence | Maturity |
|---------|----------|----------|
| GV.SI-01 | Threat intel feeds consumed (CVE, vendor advisories) | |
| GV.SI-02 | Internal context shared across teams | |
| GV.SI-03 | Information on IT/OT/IoT/CPS incidents informs decisions | |
| GV.SI-04 | Threat-informed risk assessments | |

---

## IDENTIFY (ID)

### ID.AM — Asset Management

```bash
# Endpoint inventory
rg -n "@(RequestMapping|GetMapping|PostMapping|PostMapping)" src/ --type java | wc -l

# Database inventory
rg -in "spring\.datasource|jdbc:postgresql|jdbc:mysql" src/main/resources/

# Service / topic inventory
rg -in "@KafkaListener|@RabbitListener|@JmsListener" src/ --type java
```

| Sub-cat | Evidence | Maturity |
|---------|----------|----------|
| ID.AM-01 | Hardware inventory (servers, k8s nodes) | |
| ID.AM-02 | Software inventory (SBOM) | |
| ID.AM-03 | Data flow mapped (which endpoints, which data, to where) | |
| ID.AM-04 | External systems inventoried (databases, queues, OT systems) | |
| ID.AM-05 | Resources prioritized based on classification | |
| ID.AM-07 | Data inventory (what PII / OT data is processed) | |
| ID.AM-08 | Systems / components classified by criticality | |

### ID.RA — Risk Assessment

| Sub-cat | Evidence | Maturity |
|---------|----------|----------|
| ID.RA-01 | Asset vulnerabilities identified (this audit, dependency-check) | |
| ID.RA-02 | Threat catalog for the app (OWASP Top 10 + STRIDE) | |
| ID.RA-03 | External threats considered (CVE feeds, threat intel) | |
| ID.RA-04 | Potential impacts and likelihoods of threats estimated | |
| ID.RA-05 | Threats, vulnerabilities, likelihoods, impacts used to determine risk | |
| ID.RA-06 | Risk responses chosen, prioritized, planned | |
| ID.RA-07 | Changes in OT/IT environment considered | |
| ID.RA-08 | Bias in risk assessment addressed | |
| ID.RA-09 | Suppliers prioritized by criticality and risk | |
| ID.RA-10 | Critical suppliers assessed for cybersecurity posture | |

### ID.IM — Improvement

| Sub-cat | Evidence | Maturity |
|---------|----------|----------|
| ID.IM-01 | Improvements identified from assessments (this report's remediation plan) | |
| ID.IM-02 | Improvements prioritized and implemented | |
| ID.IM-03 | Improvements tracked to completion | |
| ID.IM-04 | Post-incident improvements captured | |

### ID.SC — Supply Chain Risk Management (renamed 2.0)

See GV.SC for supply chain controls; ID.SC focuses on technical supplier integration risks.

| Sub-cat | Evidence | Maturity |
|---------|----------|----------|
| ID.SC-01 | Suppliers prioritized by criticality | |
| ID.SC-02 | Suppliers assessed for cybersecurity posture | |
| ID.SC-03 | Contracts include security requirements | |
| ID.SC-04 | Suppliers monitored for incidents and compliance | |

---

## PROTECT (PR)

### PR.AA — Identity, Authentication, and Access Control (renamed 2.0)

See OWASP A01 + A07 for code-level checks.

| Sub-cat | Spring Boot evidence | Maturity |
|---------|----------------------|----------|
| PR.AA-01 | Identities and credentials managed (users, services, certificates) | |
| PR.AA-02 | Identities proofed and bound to credentials | |
| PR.AA-03 | Users, services, hardware authenticated | |
| PR.AA-04 | Access permissions managed (RBAC, ABAC) | |
| PR.AA-05 | Access privileges minimized (least privilege) | |
| PR.AA-06 | Authentication events logged and monitored (see A09) | |

```bash
# Identify how the app authenticates
rg -n "SecurityFilterChain|@EnableWebSecurity|@PreAuthorize" src/ --type java | head -5

# Find all role definitions
rg -in "hasRole\(\"(\w+)\"\)" src/ --type java | sort -u
```

### PR.AT — Awareness and Training

| Sub-cat | Evidence | Maturity |
|---------|----------|----------|
| PR.AT-01 | Personnel trained on secure coding (Spring Boot specific) | |
| PR.AT-02 | Insider threat awareness | |
| PR.AT-03 | OT-specific training for OT-facing devs | Required for OT |
| PR.AT-04 | Board / executives trained on cyber risk | |
| PR.AT-05 | Roles include awareness on phishing, social engineering | |

### PR.DS — Data Security

See OWASP A02 + A08 for code-level checks.

| Sub-cat | Spring Boot evidence | Maturity |
|---------|----------------------|----------|
| PR.DS-01 | Data-at-rest protected (DB encryption, encrypted secrets) | |
| PR.DS-02 | Data-in-transit protected (TLS 1.2+, mTLS for OT) | |
| PR.DS-10 | Data-in-use protected (memory encryption, secure enclaves) — rare in Spring Boot | |
| PR.DS-11 | Data backups created, protected, tested (RPO / RTO) | |

### PR.PS — Platform Security

See OWASP A04 + A05 for code-level checks.

| Sub-cat | Spring Boot evidence | Maturity |
|---------|----------------------|----------|
| PR.PS-01 | Configuration management (no defaults, no dev in prod) | |
| PR.PS-02 | Software is maintained, replaced, and removed (EOL Spring Boot = non-compliant) | |
| PR.PS-03 | Hardware is maintained, replaced, and removed (out of scope) | |
| PR.PS-04 | Log records are determined, documented, implemented, reviewed | |
| PR.PS-05 | Installation and access to platform restricted (CI/CD pipeline) | |
| PR.PS-06 | Secure software development practices are integrated, and their performance is monitored throughout the SDLC | |
| PR.PS-07 | Mobile code integrity verified (rare in Spring Boot) | |
| PR.PS-08 | Cryptographic keys are managed (Vault, rotation) | |
| PR.PS-09 | Cryptographic algorithms and protocols used are current, approved, and properly implemented | |
| PR.PS-10 | Vulnerability management plan implemented | |
| PR.PS-11 | Software supply chain risk management practices implemented | |

### PR.IR — Technology Infrastructure Resilience

| Sub-cat | Spring Boot evidence | Maturity |
|---------|----------------------|----------|
| PR.IR-01 | Networks and environments protected (segmentation, mTLS, VPC) | |
| PR.IR-02 | Adequate resource capacity to ensure availability | |
| PR.IR-03 | Capacity demand managed (auto-scaling, queue throttling) | |
| PR.IR-04 | Resilience tested (chaos engineering, DR drills) | |

---

## DETECT (DE)

### DE.CM — Continuous Monitoring

```bash
# Check monitoring
rg -n "MeterRegistry|Counter\.builder|Timer\.builder|Gauge\.builder" src/ --type java
rg -n "management\.endpoint" src/main/resources/
ls docker-compose*.yml k8s/ 2>/dev/null
```

| Sub-cat | Evidence | Maturity |
|---------|----------|----------|
| DE.CM-01 | Network monitored (Prometheus, OTLP) | |
| DE.CM-02 | Physical environment monitored (datacenter) | |
| DE.CM-03 | Personnel activity monitored (audit logs) | |
| DE.CM-04 | Hardware changes detected (k8s admission, drift detection) | |
| DE.CM-05 | Software installed / removed detected (image scanning, CIS benchmarks) | |
| DE.CM-06 | External service provider activity monitored (vendor logs) | |
| DE.CM-07 | Monitoring for unauthorized personnel, connections, devices, software | |
| DE.CM-08 | Vulnerability scans performed (dependency-check, Trivy) | |
| DE.CM-09 | Computing hardware and software, runtime environments, and their data are monitored | |
| DE.CM-10 | Malicious code detected (AV / EDR on host, content scan in CI) | |
| DE.CM-11 | Malicious code removed/quarantined/alerted | |
| DE.CM-12 | System assets monitored for anomalous behavior (UEBA) | |
| DE.CM-13 | Network and information system integrity verified | |

### DE.AE — Anomaly and Event Analysis

| Sub-cat | Evidence | Maturity |
|---------|----------|----------|
| DE.AE-01 | Baselines of network and system activity collected | |
| DE.AE-02 | Detected events analyzed (SIEM rules, alerts) | |
| DE.AE-03 | Event data aggregated and correlated (SIEM, ELK, Splunk) | |
| DE.AE-04 | Correlated events triaged and prioritized | |
| DE.AE-05 | Alert thresholds established (e.g. >10 failed logins / min) | |
| DE.AE-06 | Anomaly analysis performed (UEBA, ML) | |
| DE.AE-07 | Indicators of compromise detected (IOC integration) | |
| DE.AE-08 | Cyber threat intel integrated (CVE feeds, MITRE ATT&CK) | |

---

## RESPOND (RS)

### RS.RP — Response Planning

| Sub-cat | Evidence | Maturity |
|---------|----------|----------|
| RS.RP-01 | Response plan is executed in coordination with relevant stakeholders | |
| RS.RP-02 | Response plan updated based on lessons learned | |
| RS.RP-03 | Response plan communicated to stakeholders | |
| RS.RP-04 | Response plan includes OT-specific scenarios (PL compromise, unsafe setpoint) | Required for OT |
| RS.RP-05 | Response plan includes safety considerations (e.g. fail-safe state) | Required for OT |

### RS.CO — Communications

| Sub-cat | Evidence | Maturity |
|---------|----------|----------|
| RS.CO-01 | Personnel know their roles in incident response | |
| RS.CO-02 | Incidents reported per criteria (severity, type) | |
| RS.CO-03 | Information shared with stakeholders per plan | |
| RS.CO-04 | Coordination with external stakeholders (CERT, vendor) | |
| RS.CO-05 | Voluntary external information sharing (ISAC) | |

### RS.AN — Analysis

| Sub-cat | Evidence | Maturity |
|---------|----------|----------|
| RS.AN-01 | Notifications from detection systems investigated | |
| RS.AN-02 | Impact understood (what data, what systems, what blast radius) | |
| RS.AN-03 | Forensics performed (logs, snapshots, memory) | |
| RS.AN-04 | Incidents categorized (NIST 800-61, severity levels) | |
| RS.AN-05 | Analysis considers threat intel and TTPs | |
| RS.AN-06 | Response actions informed by analysis | |
| RS.AN-07 | Root cause identified | |
| RS.AN-08 | New IOCs added to detection | |

### RS.MI — Mitigation

| Sub-cat | Spring Boot evidence | Maturity |
|---------|----------------------|----------|
| RS.MI-01 | Incidents contained (kill switch, read-only mode, force-logout) | |
| RS.MI-02 | Incidents mitigated (rollback, revoke creds, patch) | |
| RS.MI-03 | Newly identified vulnerabilities mitigated (patch) | |

```java
// Read-only / kill-switch (see also NIST 800-82 IR-4)
@ConditionalOnProperty(name = "ot.read-only", havingValue = "true")
@Service
public class PlcWriteServiceDisabled implements PlcWriteService {
    public void write(...) { throw new ReadOnlyModeException(); }
}
```

### RS.IM — Incident Recovery Improvements

| Sub-cat | Evidence | Maturity |
|---------|----------|----------|
| RS.IM-01 | Recovery plans incorporate lessons learned | |
| RS.IM-02 | Updates to response plans incorporate lessons | |
| RS.IM-03 | Incidents inform broader risk register | |
| RS.IM-04 | New IOCs update detection | |

---

## RECOVER (RC)

### RC.RP — Recovery Planning

| Sub-cat | Evidence | Maturity |
|---------|----------|----------|
| RC.RP-01 | Recovery plan executed after incident | |
| RC.RP-02 | Recovery plan updated based on lessons | |
| RC.RP-03 | Recovery plan communicated to stakeholders | |
| RC.RP-04 | Recovery plan considers safety (esp. OT) | Required for OT |
| RC.RP-05 | Recovery plan includes verification of restored system integrity | |
| RC.RP-06 | Recovery plan includes restored data integrity verification | |

### RC.IM — Improvements (renamed 2.0)

See RS.IM — overlap intentional.

### RC.CO — Communications

| Sub-cat | Evidence | Maturity |
|---------|----------|----------|
| RC.CO-01 | Public relations managed | |
| RC.CO-02 | Reputation after incident managed | |
| RC.CO-03 | Recovery activities communicated internally and externally | |
| RC.CO-04 | Recovery plans and updates communicated to stakeholders | |

---

## Maturity Assessment Method

For each sub-category, determine level:

```
1. Gather evidence (file:line, doc reference, or runbook)
2. Evaluate completeness:
   - All sub-points satisfied + tested = Compliant
   - Some sub-points satisfied OR untested = Partial
   - No evidence = Non-compliant
   - Control does not apply = N/A
3. Note evidence per cell
```

For OT integrations, mark "Required for OT" sub-categories at minimum Partial to be Compliant overall.

## Compliance Scorecard (CSF 2.0)

Per function, compute % compliant:

```
Compliant % = (Compliant count) / (Total applicable sub-categories) * 100
```

Report as:

| Function | Compliant | Partial | Non-compliant | N/A | % |
|----------|-----------|---------|---------------|-----|---|
| Govern (GV) | n | n | n | n | XX% |
| Identify (ID) | n | n | n | n | XX% |
| Protect (PR) | n | n | n | n | XX% |
| Detect (DE) | n | n | n | n | XX% |
| Respond (RS) | n | n | n | n | XX% |
| Recover (RC) | n | n | n | n | XX% |
| **TOTAL** | n | n | n | n | XX% |

## References

- NIST CSF 2.0: https://www.nist.gov/cyberframework
- NIST CSF 2.0 reference tool: https://csrc.nist.gov/Projects/cybersecurity-framework
- NIST SP 800-61 (incident handling): https://csrc.nist.gov/pubs/sp/800/61/r3/ipd
- NIST SP 800-30 (risk assessment): https://csrc.nist.gov/pubs/sp/800/30/r1/final
- CSF 2.0 small business quick start guide: https://www.nist.gov/cyberframework/small-business
