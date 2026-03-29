# Source Threat Modeling & Response Playbooks — Design Spec

Two new Claude Code skills that close the gaps at the front and back of our detection lifecycle: turning a raw data source into detection coverage, and turning detections into automated response.

## Problem

ClaudeStrike is strong at detection authoring (`behavioral-detections`, `cql-patterns`, `logscale-security-queries`) and SOC operations (triage, hunt, tune). But two lifecycle stages are weak:

1. **Pre-detection planning** — When a source has no OOTB templates, there's no structured way to reason about what threats apply, explore what the logs actually contain, and produce a detection backlog. Today this is ad hoc.
2. **Post-detection response** — The `fusion-workflows` skill provides the YAML schema and action discovery, but there's no layer that recommends *which* response actions fit *which* detections, and no playbook templates for common patterns.

## Scope

Two independent, composable skills:

- **Source Threat Modeling** — threat-model-first detection planning for sources without OOTB coverage
- **Response Playbooks** — detection-to-response mapping and playbook templates for Fusion SOAR workflows

Each skill is conversational and human-driven (Approach 1 — "Analyst Advisor"). No persistent catalogs or automation magic. Each produces handoff documents at skill boundaries for clean context transfer.

---

## Skill 1: Source Threat Modeling

### Purpose

Given a data source type, produce a prioritized detection backlog grounded in MITRE ATT&CK threat models and validated against actual log data.

### Invocation

The skill is invoked directly by the user. It does not require a handoff doc as input, though it should accept one if provided (future-proofing for upstream orchestration).

Typical entry: user says something like "I just connected Okta / GitHub / Cisco ASA and need detections."

### Workflow — 4 Phases

#### Phase 1: Source Identification

- User names the data source (product, vendor, log type)
- Skill asks clarifying questions to establish:
  - What product and log types are being ingested
  - The NGSIEM repo and/or vendor filter (e.g., `#Vendor="okta"`, `#repo="some_repo"`)
  - What the source is used for in the environment (identity, network, cloud infra, app-level)
  - Whether any detections already exist for this source (check `resources/detections/`)
- Output: a CQL scope filter that constrains all subsequent queries

#### Phase 2: Threat Modeling

- Skill reasons about threats relevant to this source type
- Approach: threat-model-first — start from "what can an attacker do that this source would observe?"
- Consider three threat categories:
  - **Abuse of the system the source monitors** (e.g., for Okta: credential stuffing, MFA bypass, session hijacking)
  - **Compromise of the source itself** (e.g., admin account takeover, audit log tampering, config changes)
  - **Lateral movement / escalation visible through the source** (e.g., privilege escalation, new admin grants)
- Map each threat scenario to MITRE ATT&CK techniques
- Output: ranked list of threat scenarios with MITRE mappings and a plain-language description of what the detection would look for

#### Phase 3: Log Validation

- For each threat scenario from Phase 2, run exploratory CQL queries against 7-30 days of live NGSIEM data
- Goals per scenario:
  - Confirm the relevant event types exist in the data
  - Understand volume and cardinality (how noisy would a detection be?)
  - Identify available fields for detection logic (what can we key on?)
  - Spot baseline patterns (what does "normal" look like for this event type?)
- Prune threat scenarios where the required events aren't present in the data
- Flag interesting or surprising patterns discovered during exploration (potential quick wins or unexpected activity)
- Output: validated threat scenarios annotated with event types, field availability, volume estimates, and feasibility notes

#### Phase 4: Detection Backlog

- Produce a prioritized list of proposed detections
- Each entry includes:
  - **Threat scenario** and plain-language description
  - **MITRE ATT&CK mapping** (technique ID + tactic)
  - **Detection approach**: simple threshold, anomaly/baseline, or behavioral correlation (`correlate()`)
  - **Estimated complexity**: low (single event match), medium (aggregation/threshold), high (multi-event correlation)
  - **Key fields and event types** from log validation
  - **Recommended authoring skill**: `behavioral-detections` for correlation rules, `cql-patterns` or `logscale-security-queries` for simpler queries
  - **Priority rationale**: why this detection matters relative to the others
- User reviews and selects which detections to pursue
- For each selected detection, skill produces a **handoff document** for the authoring skill

### Handoff Output (Producer)

When handing off to a detection authoring skill, the skill writes a handoff doc to `docs/handoffs/` with the following structure:

```yaml
source_skill: source-threat-modeling
target_skill: behavioral-detections | cql-patterns | logscale-security-queries
objective: "Author a detection for [threat scenario]"
context:
  data_source: "Okta"
  cql_scope_filter: '#Vendor="okta"'
  threat_scenario: "MFA fatigue attack — repeated MFA push denials followed by a successful auth"
  mitre_technique: "T1621 — Multi-Factor Authentication Request Generation"
  mitre_tactic: "Credential Access"
  detection_approach: "behavioral correlation"
  key_event_types:
    - "authentication.auth_via_mfa"
    - "user.authentication.auth_via_mfa_deny"
  key_fields:
    - "actor.displayName"
    - "outcome.result"
    - "client.ipAddress"
  volume_notes: "~200 MFA events/day, deny rate ~2%. Threshold of 5+ denials in 10 min should be low-noise."
decisions_made:
  - "User approved this detection for authoring"
  - "Correlation approach chosen over simple threshold — need to detect deny-then-success pattern"
constraints:
  - "120s query timeout — keep correlation window under 15 minutes"
  - "Enrich with $enrich_entra_user() if actor maps to EntraID"
artifacts: []
```

The handoff doc is a markdown file. The receiving skill reads it as its starting context.

### Interaction with Existing Skills

This skill is the **strategist**. It decides *what* to detect. Existing skills are the **craftsmen** — they decide *how* to write it:

- `behavioral-detections` — for multi-event correlation rules using `correlate()`
- `cql-patterns` — for pattern-based queries (aggregation, scoring, thresholds)
- `logscale-security-queries` — for general CQL development and investigation queries
- `detection-tuning` — downstream, once detections are deployed and need FP tuning

The skill does NOT write CQL or detection YAML itself. It produces the backlog and handoff docs; authoring is delegated.

---

## Skill 2: Response Playbooks

### Purpose

Given a detection (existing or newly proposed), recommend appropriate response actions and help wire them up as Fusion SOAR workflows. Provides a library of common response patterns and the intelligence to map detections to appropriate response tiers.

### Invocation

The skill is invoked directly by the user, or via a handoff doc from source-threat-modeling (or any other skill). Typical entries:

- "What response should I set up for this detection?"
- "I have these 5 new detections, what playbooks do they need?"
- Handoff doc from source-threat-modeling with detection context

### Workflow — 3 Phases

#### Phase 1: Detection Intake

- User points at one or more detections (by name, resource file path, or description)
- If a handoff doc is provided, read context from it
- For each detection, skill reads/understands:
  - The detection CQL and what it looks for
  - Severity level
  - MITRE ATT&CK mapping
  - **Center entity**: what's the primary subject? (user account, host, IP, cloud resource, application)
  - **Blast radius**: if this fires as a true positive, how bad is it?
- Asks clarifying questions if any of the above can't be inferred

#### Phase 2: Response Recommendation

- For each detection, propose a tiered response plan based on severity, entity type, and threat category
- Response tiers:
  - **Tier 1 — Observe**: create case, log to SIEM, notify via Slack/email. Always safe to automate.
  - **Tier 2 — Investigate**: enrich alert with additional context (host details, user history, related alerts). Safe to automate.
  - **Tier 3 — Contain**: disable user account, isolate host, revoke session, block IP. Requires human approval gate.
  - **Tier 4 — Remediate**: reset credentials, remove persistence, restore from backup. Always requires human action.
- Use `fusion-workflows` action discovery (`action_search.py`) to confirm which actions are actually available in the tenant
- Present recommendations with rationale for each tier
- Clearly distinguish:
  - "Always auto-fire" actions (Tier 1-2: case creation, notification, enrichment)
  - "Require approval" actions (Tier 3: containment actions)
  - "Manual only" actions (Tier 4: remediation)
- User reviews and approves the response plan

#### Phase 3: Workflow Generation

- For each approved response plan, produce a **handoff document** for the `fusion-workflows` skill
- The handoff doc contains everything needed to generate the workflow YAML:
  - Detection trigger (which detection fires this workflow)
  - Actions to execute, in order
  - Conditions and approval gates
  - Variables to pass between steps
- User invokes `fusion-workflows` with the handoff doc to generate and deploy the workflow

### Handoff Output (Producer)

When handing off to fusion-workflows:

```yaml
source_skill: response-playbooks
target_skill: fusion-workflows
objective: "Create a Fusion workflow for [detection name] response"
context:
  detection_name: "Okta MFA Fatigue Attack"
  detection_resource_id: "okta_mfa_fatigue"
  severity: "critical"
  center_entity: "user"
  mitre_technique: "T1621"
decisions_made:
  - "User approved tiered response plan"
  - "Tier 1 (auto): Create case with severity Critical, notify #soc-alerts Slack channel"
  - "Tier 2 (auto): Enrich with user's recent auth history (last 24h)"
  - "Tier 3 (approval required): Disable user in EntraID, revoke active sessions"
  - "Tier 4 (manual): Credential reset — SOC contacts user directly"
constraints:
  - "Tier 3 actions must have human approval gate — do not auto-execute containment"
  - "Slack notification must include: detection name, affected user, source IP, event count"
workflow_structure:
  trigger: "detection"
  actions:
    - type: "create_case"
      auto: true
    - type: "slack_notify"
      auto: true
      channel: "#soc-alerts"
    - type: "enrich_user_history"
      auto: true
    - type: "disable_entra_user"
      auto: false
      requires_approval: true
    - type: "revoke_sessions"
      auto: false
      requires_approval: true
artifacts: []
```

### Handoff Input (Consumer)

The skill accepts handoff docs from source-threat-modeling or direct user input. When consuming a handoff doc, it reads the detection context and skips Phase 1 questions that are already answered.

### Response Pattern Library

The skill carries knowledge of common response patterns. These are not persisted files — they're built into the skill's reasoning. Examples:

| Detection Type | Entity | Severity | Recommended Response |
|---|---|---|---|
| Credential attack (brute force, stuffing, MFA fatigue) | User | Critical | Case + notify + enrich + disable user (approval) |
| Privilege escalation (new admin, role change) | User | High | Case + notify + enrich + review access (manual) |
| Data exfiltration (bulk download, unusual export) | User/App | Critical | Case + notify + enrich + revoke sessions (approval) |
| Suspicious network activity (C2 beacon, unusual destination) | Host | High | Case + notify + enrich + isolate host (approval) |
| Cloud config change (security group, IAM policy) | Cloud Resource | Medium | Case + notify + enrich + revert change (manual) |
| Anomalous login (impossible travel, new device) | User | Medium | Case + notify + enrich |

These patterns inform recommendations but don't override human judgment. The skill presents them as starting points.

---

## Handoff Document Specification

Both skills produce and consume handoff documents. Standard structure:

### Format

Markdown file stored in `docs/handoffs/`. Filename convention: `YYYY-MM-DD-<source-skill>-to-<target-skill>-<brief-description>.md`

This directory is gitignored — handoff docs are ephemeral working artifacts, not permanent records.

### Required Fields

| Field | Description |
|---|---|
| `source_skill` | Which skill produced this handoff |
| `target_skill` | Which skill should consume it |
| `objective` | One-line description of what the receiving skill should accomplish |
| `context` | Structured data the receiving skill needs (source-specific) |
| `decisions_made` | List of decisions the human already approved — receiving skill should not re-ask these |
| `constraints` | Anything the receiving skill must respect |
| `artifacts` | Paths to any files created by the source skill (detection YAML, query results, etc.) |

### Lifecycle

- Handoff docs are created by the producing skill at the end of a phase
- The user invokes the receiving skill and points it at the handoff doc
- Handoff docs are working artifacts, not permanent records — they can be cleaned up after the receiving skill completes
- If the receiving skill needs to hand off further (e.g., response-playbooks → fusion-workflows), it creates a new handoff doc

---

## What's NOT In Scope

- **Data source/connector provisioning** — ingestion configuration is outside NGSIEM's API surface. The threat modeling skill assumes data is already flowing.
- **OOTB template management** — the `review-templates` command already covers this. The threat modeling skill is for sources *without* OOTB coverage.
- **Detection authoring** — delegated to existing skills via handoff docs.
- **Workflow YAML generation** — delegated to `fusion-workflows` via handoff docs.
- **Persistent source catalogs or playbook libraries** — per user decision, these are conversational skills, not knowledge-base builders.
- **Automated deployment** — both skills produce recommendations and handoff docs, not deployed resources. Deployment goes through the existing IaC pipeline.

## Relationship to Existing Skills

```
                    source-threat-modeling (NEW)
                    "what to detect"
                           |
                    handoff docs
                           |
          +----------------+----------------+
          |                |                |
  behavioral-      cql-patterns     logscale-security-
  detections       "how to write"   queries
  "how to write"                    "how to write"
          |                |                |
          +-------+--------+--------+-------+
                  |                 |
           detection-tuning    response-playbooks (NEW)
           "how to tune"       "what response"
                                    |
                              handoff doc
                                    |
                            fusion-workflows
                            "how to build workflow"
                                    |
                              IaC pipeline
                            "deploy to tenant"
```

## Skill File Structure

```
.claude/skills/
├── source-threat-modeling/
│   └── source-threat-modeling.md    # Main skill file
├── response-playbooks/
│   └── response-playbooks.md        # Main skill file
```

Each skill is a single markdown file with the skill definition — no supporting scripts or data files needed. They're conversational advisors that leverage existing infrastructure.