---
name: response-playbooks
description: >
  Detection-to-response mapping and SOAR playbook design. Analyzes detections,
  recommends tiered response actions (observe, investigate, contain, remediate),
  and produces handoff docs for fusion-workflows to generate workflow YAML.
  Use when planning response automation for detections, designing SOAR playbooks,
  or mapping detections to Falcon Fusion workflow actions.
allowed-tools: Read, Write, Grep, Glob, Bash
---

# Response Playbooks

Turn detections into automated response. This skill analyzes what a detection looks for, recommends tiered response actions appropriate to the threat, and hands off to `fusion-workflows` for workflow YAML generation. It bridges the gap between "alert fires" and "something happens."

> **Response architect, not workflow builder.** This skill decides *what response* fits a detection. The `fusion-workflows` skill builds the actual workflow YAML.

## When to Use This Skill

- You have detections deployed (or proposed) and need response automation
- You want to design SOAR playbooks for a set of detections
- You need to map detection severity/type to appropriate response actions
- You're deciding which detections warrant automated containment vs. notification-only

## Handoff Input

This skill accepts:
- **Direct invocation** — user points at detections by name, file path, or description
- **Handoff doc from source-threat-modeling** — read the doc and use its context for Phase 1

If consuming a handoff doc, skip Phase 1 questions already answered in the doc.

---

## Phase 1: Detection Intake

**Goal:** Understand what each detection looks for and what's at stake.

For each detection the user wants response automation for:

### Step 1: Read the detection

- If it's a deployed detection: read from `resources/detections/`
- If it's from a handoff doc: read the context provided
- If described verbally: ask enough questions to understand the threat

Gather:
- Detection name and CQL logic
- Severity level
- MITRE ATT&CK mapping (technique + tactic)

### Step 2: Identify the center entity

What is the primary subject of this detection?

| Entity Type | Examples |
|---|---|
| User account | Identity-based threats — credential attacks, privilege escalation |
| Host/endpoint | Malware, LOLBins, persistence, lateral movement |
| IP address | Network-based threats — C2, scanning, exfiltration |
| Cloud resource | Infrastructure threats — config changes, IAM abuse |
| Application | SaaS/app-level threats — data theft, API abuse |

### Step 3: Assess blast radius

If this detection fires as a true positive, how bad is it?

| Blast Radius | Meaning | Examples |
|---|---|---|
| **Critical** | Active compromise, data loss in progress | Ransomware, active exfiltration, admin account takeover |
| **High** | Escalation or movement underway | Privilege escalation, lateral movement, credential theft |
| **Medium** | Suspicious but contained | Policy violation, anomalous login, config change |
| **Low** | Informational, worth tracking | New device, unusual time of day, minor anomaly |

**Present the intake summary** (detection, entity, blast radius) and confirm with user before proceeding.

**STOP** — Get user confirmation on the intake assessment.

---

## Phase 2: Response Recommendation

**Goal:** Propose a tiered response plan for each detection.

### Response Tiers

| Tier | Name | Automation Level | Description |
|---|---|---|---|
| **Tier 1** | Observe | Always auto-fire | Create case, log event, notify Slack/email |
| **Tier 2** | Investigate | Always auto-fire | Enrich alert with host details, user history, related alerts |
| **Tier 3** | Contain | Requires human approval | Disable user, isolate host, revoke session, block IP |
| **Tier 4** | Remediate | Manual only | Reset credentials, remove persistence, restore from backup |

### Recommendation Process

For each detection:

**1. Tier 1 — Observe (every detection gets this)**

- Create case with appropriate severity
- Notify the relevant channel (Slack, email, PagerDuty based on severity)
- Log to SIEM for correlation

**2. Tier 2 — Investigate (based on center entity)**

| Entity Type | Enrichment Actions |
|---|---|
| User account | Recent auth history, group memberships, risk score, MFA status |
| Host/endpoint | Running processes, network connections, login history, installed software |
| IP address | Geo lookup, reputation check, historical connections, associated users |
| Cloud resource | Config change history, access logs, associated IAM roles |
| Application | Recent API calls, data access patterns, admin actions |

**3. Tier 3 — Contain (based on severity + threat type)**

| Severity | Threat Type | Containment Recommendation |
|---|---|---|
| Critical | Active attack (exfil, ransomware, admin takeover) | Immediate containment with approval gate |
| Critical | Credential compromise (MFA fatigue, brute force success) | Disable user + revoke sessions with approval gate |
| High | Lateral movement | Isolate host with approval gate |
| High | Privilege escalation | Suspend elevated access with approval gate |
| Medium or below | Any | Skip containment — observe and investigate only |

**Every Tier 3 action MUST have a human approval gate.** Never auto-execute containment. False positive containment is worse than delayed response.

**4. Tier 4 — Remediate (always manual, but document it)**

Document what the SOC should do after containment:
- Credential reset procedures
- Host reimaging steps
- Config rollback process
- Evidence preservation requirements
- Scope assessment (who/what else was affected?)

### Validate available actions

Before recommending, confirm what's actually available in the tenant:

```bash
python .claude/skills/fusion-workflows/scripts/action_search.py --vendor <vendor>
python .claude/skills/fusion-workflows/scripts/action_search.py --use-case <use-case>
```

Only recommend actions that are available. If a recommended action isn't available, note it as a gap and suggest alternatives.

### Present the response plan

For each detection, present:

```
Detection: <name>
Severity: <severity> | Entity: <entity type> | Threat: <MITRE tactic>

Tier 1 (auto):
  - Create case (severity: <X>)
  - Notify <channel> with: detection name, affected entity, key indicators

Tier 2 (auto):
  - <specific enrichment actions>

Tier 3 (approval required):
  - <containment action> — requires SOC analyst approval

Tier 4 (manual):
  - <remediation steps for SOC to execute>
```

**STOP** — Get user approval on the response plan before generating handoff docs.

---

## Phase 3: Workflow Generation & Handoff

**Goal:** Produce handoff documents for `fusion-workflows` to build the actual workflow YAML.

For each approved response plan, write a handoff doc to `docs/handoffs/`.

**Filename:** `YYYY-MM-DD-response-playbooks-to-fusion-workflows-<detection-name>.md`

**Template:**

```markdown
# Handoff: Response Playbooks → Fusion Workflows

## Objective

Create a Fusion workflow to automate response for: <detection name>

## Source

- **Produced by:** response-playbooks skill
- **Date:** <today>
- **Target skill:** fusion-workflows

## Context

| Field | Value |
|---|---|
| Detection name | <name> |
| Detection resource_id | <id, if deployed> |
| Severity | <severity> |
| Center entity | <entity type> |
| MITRE technique | <ID> — <name> |
| MITRE tactic | <tactic> |

## Approved Response Plan

### Tier 1 — Observe (auto-fire)

- **Create case** — severity: <X>, title template: "<detection name> — <entity value>"
- **Notify** — channel: <channel>, include: detection name, affected entity, source IP, event count

### Tier 2 — Investigate (auto-fire)

- **Enrich** — <specific actions and what data to pull>

### Tier 3 — Contain (approval required)

- **<Action>** — <details>
- **Approval gate:** SOC analyst must approve before execution via <mechanism>

### Tier 4 — Remediate (manual)

- <Steps for SOC to execute manually after containment>

## Decisions Made

These have been reviewed and approved by the user. The receiving skill should NOT re-ask:

- <decision 1>
- <decision 2>

## Constraints

- Tier 3 actions MUST have a human approval gate — never auto-execute containment
- Notification must include: <required fields>
- <any tenant-specific constraints>

## Workflow Structure

- **Trigger:** Detection alert (detection name: <name>)
- **Flow:** Tier 1 actions → Tier 2 enrichment → conditional Tier 3 containment (with approval)
- **Approval mechanism:** <how the approval gate should work>

## Artifacts

- <paths to any files from earlier phases, or "None">
```

**Tell the user:** "Handoff doc written to `<path>`. Invoke the `fusion-workflows` skill and point it at this file to generate the workflow YAML."

---

## Response Pattern Library

Common detection-to-response mappings. These inform recommendations but don't override human judgment — use them as starting points.

| Detection Type | Entity | Severity | Tier 1 | Tier 2 | Tier 3 | Tier 4 |
|---|---|---|---|---|---|---|
| Credential attack (brute force, stuffing, MFA fatigue) | User | Critical | Case + Slack | Auth history, risk score | Disable user, revoke sessions | Credential reset |
| Privilege escalation (new admin, role change) | User | High | Case + Slack | Access audit, change history | — | Review and revert access |
| Data exfiltration (bulk download, unusual export) | User/App | Critical | Case + Slack | Download history, data classification | Revoke sessions, block IP | Audit data exposure |
| Suspicious network (C2 beacon, unusual dest) | Host | High | Case + Slack | Process list, network connections | Isolate host | Reimage, hunt for lateral |
| Cloud config change (SG, IAM policy) | Cloud Resource | Medium | Case + Slack | Config diff, who-changed-what | — | Revert change |
| Anomalous login (impossible travel, new device) | User | Medium | Case + Slack | Login history, device inventory | — | — |
| Audit log tampering | Source | Critical | Case + Slack + page | Log gap analysis | Isolate source, freeze state | Forensic investigation |
| Service account abuse | User | High | Case + Slack | Service account scope, recent API calls | Rotate credentials | Audit all service account access |

---

## Key Principles

1. **Never auto-execute containment.** Tier 3 actions always require human approval. False positive containment is worse than delayed response.
2. **Every detection gets Tier 1.** At minimum: create a case and notify someone.
3. **Match response to blast radius.** A medium-severity anomalous login doesn't need host isolation.
4. **Validate before recommending.** Use action discovery to confirm what's available in the tenant.
5. **Document Tier 4 even though it's manual.** The SOC needs to know what comes after containment.
