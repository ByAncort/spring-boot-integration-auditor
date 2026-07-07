# Triage — Spring Boot Integration Auditor

> Part of the `spring-boot-integration-auditor` skill — back to [SKILL.md](../SKILL.md)

## Purpose

Diagnose scope, criticality and context before running the audit. **Max 3 questions, one at a time**. If the user already gave sufficient context (e.g. "audit C:\projects\scada-integration critical full"), skip triage.

---

## Triage Tree

### Step 1 — Identify the integration

> Which Spring Boot integration do you need to audit? Provide the path to the repository.

| User response | Route |
|---------------|-------|
| Valid path with `pom.xml` or `build.gradle` Spring | -> Step 2 |
| Valid path without build files | -> Verify stack (Step 1B) |
| Name without path (e.g. "the payments microservice") | -> Ask for path |
| User does not know the path | -> Ask to locate the project |

**Path verification command:**
```bash
Test-Path <path>
Test-Path <path>/pom.xml
Test-Path <path>/build.gradle
```

### Step 1B — Verify Spring Boot stack

If `pom.xml` or `build.gradle` exists, verify Spring dependencies:

```bash
# Maven
Select-String -Path "<path>/pom.xml" -Pattern "spring-boot-starter"

# Gradle
Select-String -Path "<path>/build.gradle" -Pattern "spring-boot-starter"
```

| Result | Decision |
|--------|----------|
| Contains `spring-boot-starter-*` | -> Continue to Step 2 |
| Does not contain Spring | Inform: "The project at [path] does not appear to be Spring Boot. This skill audits Spring Boot projects exclusively. For [Node/Python/.NET] use the stack-specific skill." and stop. |
| Only `spring-framework` (without Boot) | Inform: "Detected Spring Framework without Boot. This skill assumes Spring Boot. Some checks (Actuator, autoconfig) will not apply." Ask if continue. |

### Step 2 — Determine operational criticality

> What is the operational criticality of this integration? Does it affect OT/ICS systems, core processes, or is it support/admin only?

| Level | Criteria |
|-------|----------|
| **Critical** (default if uncertain) | Connects to OT/ICS systems (SCADA, PLC, DCS, Historian, OPC UA, Modbus, industrial MQTT broker). Compromise or failure stops production or affects physical safety. Example: Spring Boot <-> PLC integration via OPC UA. |
| **High** | Processes operational, financial, or PII data. Connects to core systems (ERP, CRM, billing, planning). |
| **Medium** | Operational support. Logistics, reporting, internal microservice-to-microservice integrations. |
| **Low** | Administrative/internal. No direct operational impact (admin CRUD, internal dashboard, dev tooling). |

**Quick inference heuristic** (no need to ask if there are clear signals):
- Mentions "SCADA", "PLC", "Modbus", "OPC UA", "historian", "OT", "ICS", "mining", "manufacturing" -> Critical
- Mentions "billing", "payments", "ERP", "PII", "production" -> High
- Default if no signals -> ask for confirmation

### Step 3 — Determine scope

> What scope do you need?

| Option | Frameworks included | Estimated time |
|--------|---------------------|----------------|
| **Full** (recommended for Critical/High) | OWASP + 800-82 + CSF | 30-45 min |
| **OWASP + 800-82** | No CSF, technical focus | 20-30 min |
| **OWASP Top 10 only** | A01-A10 with Spring patterns | 10-15 min |
| **NIST SP 800-82 only** | ICS controls (for OT-facing) | 15-20 min |
| **NIST CSF only** | Organizational maturity, no deep scan | 10-15 min |
| **Quick** (automated scans only) | dependency-check + gitleaks + endpoints | 3-5 min |

### Step 4 — Confirm and execute

Show the summary before starting:

```markdown
## Audit configured

| Parameter | Value |
|-----------|-------|
| Integration | [name] |
| Repository | [absolute path] |
| Stack | Spring Boot [version] · Java [version] |
| Criticality | [Critical/High/Medium/Low] |
| Scope | [Full/OWASP/800-82/CSF/Quick] |
| Frameworks | [list] |

Starting Phase A (reconnaissance)...
```

Then proceed to execute the "Execution Flow" section in SKILL.md.

---

## Quick Mapping (phrase -> configuration)

| User phrase | Diagnosis |
|-------------|-----------|
| "audit this integration" + path | Step 1 with path -> verify Spring |
| "audit the SCADA integration" without path | Ask for path |
| "review security of [name]" | Step 1 without path -> ask for path |
| "I only want OWASP" | Scope: OWASP |
| "it's for an internal demo" | Criticality: Low |
| "connects to SCADA" / "is OT-facing" | Criticality: Critical |
| "it's an internal microservice" | Criticality: Medium |
| "need compliance for external audit" | Scope: Full |
| "only automated scans" | Scope: Quick |
| "quick check before deploy" | Scope: Quick · If High/Critical -> suggest Full |
| "for a mining/manufacturing/ICS" | Criticality: Critical (assume OT) |
| "Spring Boot 2.x" | Stack detection: medium finding (EOL) |
| "mvn spring-boot:run doesn't work" | Inform: the audit does NOT require running the app. Read code + external tools only. |
| "I don't have gitleaks" | Continue with grep fallback. Do not block. |

---

## Triage Rules

1. **One question at a time**. Do not ask all 3 questions together.
2. **If the user already said everything**, skip redundant questions.
3. **If the path does not exist**, inform: "The path [path] does not exist or is not accessible. Verify the route." Do not advance.
4. **If it is not Spring Boot**, inform and stop. Do not waste time guessing.
5. **For High/Critical criticality, always suggest Full scope** even if the user asks for Quick. If they insist:
   > "For a [criticality level] integration with [connected systems], I recommend a full audit. Automated scans do not detect network segmentation issues, ICS controls, or organizational maturity. Continue with [requested scope] anyway? (yes/no)"
6. **Max triage time**: 2 minutes or 3 questions, whichever comes first.
7. **Do not run tools** during triage. Only verify paths and read manifest files.
