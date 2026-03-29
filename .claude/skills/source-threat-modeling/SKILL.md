---
name: source-threat-modeling
description: >
  Threat-model-first detection planning for data sources without OOTB coverage.
  Analyzes what threats apply to a source type, validates against live log data,
  and produces a prioritized detection backlog with handoff docs for authoring skills.
  Use when onboarding a new data source, planning detection coverage for a source
  without OOTB templates, or assessing what threats a source can detect.
allowed-tools: Read, Write, Grep, Glob, Bash
---

# Source Threat Modeling

Turn a data source into detection coverage. This skill reasons about what threats are relevant to a source type, validates which are detectable in your actual log data, and produces a prioritized detection backlog. It does NOT write detections — it hands off to authoring skills (`behavioral-detections`, `cql-patterns`, `logscale-security-queries`) via handoff documents.

> **Orchestrator, not author.** This skill decides *what* to detect. Existing skills decide *how* to write it.

## When to Use This Skill

- A new data source is connected to NGSIEM and has no OOTB detection templates
- You want to assess detection coverage gaps for an existing source
- You need a structured threat model before building bespoke detections
- You're onboarding a source type you haven't worked with before

## Handoff Input

This skill can be invoked directly or via a handoff document. If a handoff doc is provided, read it first and skip questions already answered.

---

## Phase 1: Source Identification

**Goal:** Establish what source we're working with and how to query it.

Ask the user:

1. **What product/vendor is the data source?** (e.g., Okta, GitHub audit logs, Cisco ASA, Zscaler)
2. **What log types are being ingested?** (authentication, admin activity, network flow, API audit, etc.)
3. **What is the NGSIEM scope filter?**
   - e.g., `#Vendor="okta"`, `#repo="some_repo"`, `#event.module="some_module"`
   - If the user doesn't know, help discover it:
     ```
     * | groupBy([@repo, #Vendor, #event.module], limit=20)
     ```
4. **What role does this source play in the environment?** (identity provider, network perimeter, cloud infrastructure, application-level, endpoint, email/collaboration)

**Check for existing coverage:**
- Scan `resources/detections/` for any rules already targeting this source
- Note what's covered so we don't duplicate

**Output:** A CQL scope filter and source profile that constrains all subsequent work.

**STOP** — Confirm the scope filter and source profile with the user before proceeding to threat modeling.

---

## Phase 2: Threat Modeling

**Goal:** Enumerate threats this source can observe, mapped to MITRE ATT&CK.

Work through three threat categories systematically:

### Category A: Abuse of the monitored system

What can an attacker do *through* the system this source monitors?

| Source Role | Example Threats |
|---|---|
| Identity provider | Credential stuffing, MFA bypass, session hijacking, account takeover |
| Network perimeter | C2 communication, lateral movement, data exfiltration, port scanning |
| Cloud infrastructure | Resource abuse, privilege escalation, config tampering, data access |
| Application | Injection, unauthorized access, data theft, API abuse |
| Endpoint | Malware execution, LOLBins, persistence mechanisms, credential dumping |
| Email/collaboration | Phishing, BEC, forwarding rules, delegation abuse |

### Category B: Compromise of the source itself

What does it look like when the source system is the target?
- Admin account takeover on the source platform
- Audit log tampering or deletion
- Security configuration changes (weakened settings)
- API key or token compromise
- Integration or connector manipulation

### Category C: Lateral movement and escalation

What cross-system activity is visible through this source?
- Privilege escalation (new admin grants, role changes)
- Cross-tenant or cross-account activity
- Service account abuse
- Access to new resources or scopes not previously seen

**For each threat scenario, document:**

| Field | Description |
|---|---|
| Threat scenario | Plain-language description of the attack |
| MITRE technique | ATT&CK technique ID (e.g., T1621) |
| MITRE tactic | ATT&CK tactic (e.g., Credential Access) |
| Expected event types | What log events would reveal this activity |
| Expected severity | Critical / High / Medium / Low |

**Present the threat model to the user as a ranked table.** Rank by severity and likelihood. Discuss and refine before proceeding to log validation.

**STOP** — Get user approval on the threat model before querying live data.

---

## Phase 3: Log Validation

**Goal:** Confirm which threats from Phase 2 are actually detectable in the live data.

For each threat scenario, run exploratory CQL queries using `mcp__crowdstrike__ngsiem_query`:

### Step 1: Event type discovery

Map what the source actually emits:

```
<scope_filter>
| groupBy([event.type, event.action, event.category], limit=50)
```

### Step 2: Per-scenario validation

For each threat scenario from Phase 2:

**a) Do the required event types exist?**
```
<scope_filter> event.type="<expected_type>"
| count()
```

**b) What's the volume?** (informs threshold decisions)
```
<scope_filter> event.type="<expected_type>"
| bucket(span=1d)
| count()
```

**c) What fields are available?** (informs detection logic)
```
<scope_filter> event.type="<expected_type>"
| head(10)
```

**d) What does "normal" look like?** (informs baselines)
```
<scope_filter> event.type="<expected_type>"
| groupBy([<key_field>], function=count())
| sort(_count, order=desc)
| head(20)
```

### Step 3: Feasibility classification

For each threat scenario, classify:

| Classification | Meaning | Action |
|---|---|---|
| **Detectable** | Required events exist, fields available, reasonable volume | Keep — proceed to backlog |
| **Partially detectable** | Some events present but missing key fields or context | Discuss with user — worth pursuing with limitations? |
| **Not detectable** | Required events don't exist in the data | Prune from backlog |
| **Surprising find** | Unexpected patterns worth investigating | Flag for user — potential quick win or live incident |

**Present results.** For each scenario, show: classification, event types found, key fields available, daily volume estimate, and any surprising observations.

**STOP** — Discuss findings with user. Prune not-detectable scenarios. Decide on partial detections.

---

## Phase 4: Detection Backlog & Handoff

**Goal:** Produce a prioritized detection backlog and hand off selected detections to authoring skills.

### Build the backlog

For each validated threat scenario, create a backlog entry:

| Field | Description |
|---|---|
| **Priority** | 1 (highest) through N — based on severity + feasibility |
| **Threat scenario** | Plain-language description |
| **MITRE mapping** | Technique ID + tactic |
| **Detection approach** | `simple` (single event match), `threshold` (aggregation), `behavioral` (multi-event correlation) |
| **Complexity** | Low (single event) / Medium (aggregation/threshold) / High (multi-event correlation) |
| **Key event types** | From log validation |
| **Key fields** | From log validation |
| **Volume estimate** | Events/day from log validation |
| **Recommended skill** | Which authoring skill should build this |

### Skill routing

| Detection Approach | Route To | Why |
|---|---|---|
| Multi-event attack chains (deny-then-success, create-then-escalate) | `behavioral-detections` | Needs `correlate()` function |
| Threshold/aggregation rules (N events in T time) | `cql-patterns` | Pattern-based aggregation |
| Simple event matching or complex field logic | `logscale-security-queries` | General CQL development |

### Present the backlog

Show the full backlog as a prioritized table. User selects which detections to pursue.

### Generate handoff documents

For each selected detection, write a handoff doc to `docs/handoffs/`.

**Filename:** `YYYY-MM-DD-threat-model-to-<target-skill>-<brief-description>.md`

**Template:**

```markdown
# Handoff: Source Threat Modeling → <Target Skill>

## Objective

Author a detection for: <threat scenario one-liner>

## Source

- **Produced by:** source-threat-modeling skill
- **Date:** <today>
- **Target skill:** <behavioral-detections | cql-patterns | logscale-security-queries>

## Context

| Field | Value |
|---|---|
| Data source | <source name> |
| CQL scope filter | `<filter>` |
| Source role | <identity / network / cloud / app / endpoint> |
| Threat scenario | <description> |
| MITRE technique | <ID> — <name> |
| MITRE tactic | <tactic> |
| Detection approach | <simple / threshold / behavioral> |
| Estimated severity | <Critical / High / Medium / Low> |

### Key Event Types

- `<event.type>` — <what it represents>

### Key Fields

- `<field>` — <what it contains, example values>

### Volume Notes

<daily volume estimate and baseline observations from Phase 3>

## Decisions Made

These have been reviewed and approved by the user. The receiving skill should NOT re-ask:

- <decision 1>
- <decision 2>

## Constraints

- 120s NGSIEM query timeout — keep correlation windows reasonable
- <any source-specific constraints discovered during exploration>
- <relevant enrichment functions from detection-tuning, if applicable>

## Artifacts

- <paths to any files created during this session, or "None">
```

**Tell the user:** "Handoff doc written to `<path>`. Invoke the `<target-skill>` skill and point it at this file to begin authoring."

---

## Reference: Common Source Types

| Source Category | Examples | Typical Threat Focus |
|---|---|---|
| Identity Provider | Okta, EntraID, Ping, Auth0 | Credential attacks, MFA bypass, admin takeover, privilege escalation |
| Cloud Infrastructure | AWS CloudTrail, GCP Audit, Azure Activity | Resource abuse, IAM escalation, config tampering, data access |
| Network Security | Cisco ASA, Palo Alto, Zscaler, Akamai | C2 comms, lateral movement, exfiltration, scanning |
| Source Code / DevOps | GitHub, GitLab, Bitbucket | Code theft, secret exposure, pipeline compromise, access changes |
| SaaS Applications | Salesforce, Workday, ServiceNow | Data exfiltration, privilege abuse, config changes |
| Endpoint | CrowdStrike EDR, Carbon Black, SentinelOne | Malware, LOLBins, persistence, credential dumping |
| Email / Collaboration | M365, Google Workspace | Phishing, BEC, forwarding rules, delegation abuse |

This table is a starting point for Phase 2 — reason about threats specific to the actual product, not just the category.
