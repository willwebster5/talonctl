# Threat Hunting Skill Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement a standalone, autonomous threat hunting Claude Code skill that executes the PEAK framework (Prepare → Execute → Act) across three hunt types, producing hunt reports, detection backlogs, and visibility gap reports.

**Architecture:** Single skill file (SKILL.md) with a `/hunt` command router, two living documents (hunt log, ATT&CK coverage map), and integration into the existing detection lifecycle via handoff docs. The skill runs autonomously through all three PEAK phases with human touchpoints only at escalation and final review.

**Tech Stack:** Claude Code skill (markdown), CrowdStrike MCP tools, CQL queries, YAML handoff docs.

**Spec:** `docs/superpowers/specs/2026-03-28-threat-hunting-skill-design.md`

---

### Task 1: Scaffold directories and gitignore

**Files:**
- Create: `.claude/skills/threat-hunting/` (directory)
- Create: `.claude/skills/threat-hunting/memory/` (directory)
- Create: `docs/hunts/.gitkeep`
- Create: `docs/handoffs/.gitignore`
- Modify: `.gitignore`

- [ ] **Step 1: Create the skill directory structure**

```bash
mkdir -p .claude/skills/threat-hunting/memory
```

- [ ] **Step 2: Create docs/hunts/ with .gitkeep**

Hunt reports are permanent archival records — this directory is committed to git.

```bash
mkdir -p docs/hunts
```

Write `docs/hunts/.gitkeep` as an empty file:

```
```

- [ ] **Step 3: Create docs/handoffs/ with its own .gitignore**

Handoff docs are ephemeral working artifacts. The directory itself is tracked, but its contents are gitignored.

```bash
mkdir -p docs/handoffs
```

Write `docs/handoffs/.gitignore`:

```
# Handoff docs are ephemeral working artifacts — not permanent records.
# They are created by one skill and consumed by another, then cleaned up.
*
!.gitignore
```

- [ ] **Step 4: Verify directory structure**

Run: `find .claude/skills/threat-hunting docs/hunts docs/handoffs -type f -o -type d | sort`

Expected:
```
.claude/skills/threat-hunting
.claude/skills/threat-hunting/memory
docs/handoffs
docs/handoffs/.gitignore
docs/hunts
docs/hunts/.gitkeep
```

- [ ] **Step 5: Commit**

```bash
git add .claude/skills/threat-hunting docs/hunts/.gitkeep docs/handoffs/.gitignore
git commit -m "scaffold: threat-hunting skill directories and docs/hunts, docs/handoffs"
```

---

### Task 2: Living document templates

**Files:**
- Create: `.claude/skills/threat-hunting/memory/hunt-log.md`
- Create: `.claude/skills/threat-hunting/memory/coverage-map.md`

- [ ] **Step 1: Write hunt-log.md**

Write `.claude/skills/threat-hunting/memory/hunt-log.md`:

```markdown
<!-- LIVING DOCUMENT
Updated by the threat-hunting skill after every completed hunt.
Append-only — one row per hunt. Do not delete entries.
Used during Prepare phase to avoid redundant hunts and during
/hunt (no args) to summarize hunting activity. -->

# Hunt Log

| Date | Type | Title | ATT&CK | Outcome | Detections Proposed |
|------|------|-------|--------|---------|---------------------|
```

- [ ] **Step 2: Write coverage-map.md**

Write `.claude/skills/threat-hunting/memory/coverage-map.md`:

```markdown
<!-- LIVING DOCUMENT
Updated by the threat-hunting skill after every completed hunt.
Tracks the HUNT LAYER — what has been proactively hunted.
Cross-referenced during Prepare against deployed detection MITRE
mappings from resources/detections/ to identify high-value targets.

Three categories of high-value hunt targets:
1. Blind spots — no detections AND no hunting (highest priority)
2. Untested assumptions — detections exist but never hunted
3. Stale coverage — not hunted in 90+ days -->

# ATT&CK Hunt Coverage Map

## Hunted

| Technique | Tactic | Last Hunted | Result | Data Quality |
|-----------|--------|-------------|--------|--------------|

## Known Gaps

| Technique | Tactic | Reason | Recommendation |
|-----------|--------|--------|----------------|

## Suggested Priority Hunts

_No hunts completed yet. After the first hunt, this section will be populated with recommendations based on gaps, staleness, and untested detection coverage._
```

- [ ] **Step 3: Verify files exist and read correctly**

Run: `cat .claude/skills/threat-hunting/memory/hunt-log.md && echo "---" && cat .claude/skills/threat-hunting/memory/coverage-map.md`

Expected: Both files display with correct markdown table headers and HTML comments.

- [ ] **Step 4: Commit**

```bash
git add .claude/skills/threat-hunting/memory/hunt-log.md .claude/skills/threat-hunting/memory/coverage-map.md
git commit -m "feat: add threat-hunting living document templates (hunt log + coverage map)"
```

---

### Task 3: DESIGN.md — architecture rationale

**Files:**
- Create: `.claude/skills/threat-hunting/DESIGN.md`

- [ ] **Step 1: Write DESIGN.md**

Write `.claude/skills/threat-hunting/DESIGN.md`:

```markdown
# Threat Hunting Skill — Architecture Rationale

## Problem

ClaudeStrike's hunting capability is a 6-step subcommand (`/soc hunt`) with no structured preparation, no post-hunt outputs, no feedback loop into detection engineering, and no institutional knowledge accumulation. The research literature establishes that hunting's compounding value comes from the hunting → detection engineering pipeline. ClaudeStrike has the downstream skills (`behavioral-detections`, `cql-patterns`, `detection-tuning`) but no structured upstream practice feeding them.

## Architecture: Autonomous PEAK Framework

This skill implements the PEAK framework (Prepare → Execute → Act) as an autonomous agent — minimal human-in-the-loop, with escalation as the primary interrupt.

### Why Autonomous (vs. Phased with Human Gates)

The SOC skill uses phased architecture with human checkpoints to prevent confirmation bias during triage. Hunting has a different dynamic — the agent is exploring, not reacting to an alert. Rigid gates fight the exploratory nature of hunting. The agent drives end-to-end; humans provide the trigger and review outputs.

### Why Three Hunt Types

PEAK recognizes three types: hypothesis-driven, baseline (anomaly), and model-assisted (intelligence-driven in our case). CrowdStrike's NGSIEM supports all three — CQL handles stacking natively for baseline hunts, `ngsiem_query` supports ad-hoc hypothesis testing, and IOC/TTP sweeps work for intelligence-driven hunts.

### Why Standalone (vs. Replacing /soc hunt)

Clean separation of concerns. `/soc hunt` stays as a quick ad-hoc mode for simple IOC sweeps during triage. This skill handles the full PEAK lifecycle — scoping, execution, detection backlog, gap reporting, self-evaluation.

### Why Lightweight Living Documents

A hunt log prevents redundant work. An ATT&CK coverage map enables gap-based prioritization. Baselines are better expressed as saved CQL queries or detection rules than memory files. Hypothesis backlogs are project management, not skill memory.

### Why Tiered Escalation

Real hunt teams don't stop investigating at the first suspicious finding. They establish scope first. But confirmed active compromise (C2, exfiltration, lateral movement) demands immediate containment. "Does this need containment?" is the decision boundary.

## Key Design Decisions

| Decision | Choice |
|---|---|
| Relationship to `/soc hunt` | Standalone — independent skill |
| Hunt types | Hypothesis, intelligence, baseline |
| Human-in-the-loop | Minimal — agentic, escalation is the interrupt |
| Outputs | Hunt report + detection backlog + gap report |
| Living documents | Hunt log + ATT&CK coverage map |
| Escalation | Tiered — continue for suspected, hard stop for active compromise |
| Self-evaluation | Part of Act phase, feeds coverage map |

## Integration Points

- **Upstream:** Human invocation, coverage map suggestions, source-threat-modeling handoffs, SOC triage findings, external intel
- **Downstream:** Detection authoring skills (via handoff docs), SOC skill (via escalation handoff), source-threat-modeling (via gap reports)
- **Shared context:** `environmental-context.md` and `investigation-techniques.md` from the SOC skill

## Research Foundation

Design grounded in the threat hunting research survey. Key concepts: PEAK framework (Bianco et al., 2023), Hunting Maturity Model (targeting HM4), Pyramid of Pain, stacking/long-tail analysis, hunt → detection engineering feedback loop.

## Full Spec

`docs/superpowers/specs/2026-03-28-threat-hunting-skill-design.md`
```

- [ ] **Step 2: Verify file reads correctly**

Run: `head -20 .claude/skills/threat-hunting/DESIGN.md`

Expected: Title and Problem section display correctly.

- [ ] **Step 3: Commit**

```bash
git add .claude/skills/threat-hunting/DESIGN.md
git commit -m "docs: add threat-hunting skill architecture rationale"
```

---

### Task 4: SKILL.md — frontmatter, persona, tools, CQL patterns

**Files:**
- Create: `.claude/skills/threat-hunting/SKILL.md`

This task creates the first portion of SKILL.md — the skill identity, persona, principles, MCP tool reference, and hunting-specific CQL patterns. Subsequent tasks append the phase architecture.

- [ ] **Step 1: Write SKILL.md with frontmatter, persona, tools, and CQL patterns**

Write `.claude/skills/threat-hunting/SKILL.md`:

```markdown
---
name: threat-hunting
description: Autonomous threat hunting using the PEAK framework (Prepare → Execute → Act). Executes hypothesis-driven, intelligence-driven, and baseline hunts against CrowdStrike NG-SIEM. Produces hunt reports, detection backlogs, and visibility gap reports. Use when proactively hunting for threats, validating detection coverage, or responding to new threat intelligence.
---

> Threat hunting skill loaded — PEAK framework (Prepare → Execute → Act). Sub-skills: `logscale-security-queries` (CQL), `cql-patterns` (query patterns), `behavioral-detections` (correlation rules).

# Threat Hunting — Autonomous PEAK-Based Hunting

Autonomous threat hunter operating inside a CrowdStrike NG-SIEM environment. Assumes breach. Follows leads. Produces actionable outputs.

## Persona & Principles

You are an autonomous threat hunter. You drive the full PEAK lifecycle without human gates between phases. The human provides the trigger and reviews your outputs.

- **Assume breach.** The environment is compromised until proven otherwise. Your job is to find what automated defenses missed.
- **Follow leads.** When you find something interesting, pivot — correlate across data sources, expand scope, dig deeper. Don't stop at the first query.
- **No hunt fails.** A hunt that finds no threats validates coverage, identifies visibility gaps, and strengthens baselines. Every hunt produces value.
- **IOCs are ephemeral, TTPs are durable.** When hunting from intelligence, escalate from indicators (hashes, IPs, domains) to behaviors (process chains, persistence patterns, lateral movement). Climb the Pyramid of Pain.
- **Feed the pipeline.** Every pattern you discover that could be automated should become a proposed detection. The hunting → detection engineering feedback loop is where compounding value lives.
- **Know your data.** Before running queries, confirm the data source exists and the fields are correct. Consult `investigation-techniques.md` for repo mappings and field gotchas. A query against the wrong repo returns 0 results silently.
- **Escalate active threats immediately.** If you discover confirmed active compromise (C2, exfiltration, lateral movement in progress), stop hunting and produce an escalation package. "Does this need containment?" is the decision boundary.

## Available Tools

**CrowdStrike MCP tools** — call these directly as MCP tool invocations. Do NOT write Python scripts or wrapper code.

### Hunting & Investigation
| MCP Tool | Purpose |
|----------|---------|
| `mcp__crowdstrike__ngsiem_query` | Execute CQL queries — the primary hunting tool. Multiple queries per hunt. |
| `mcp__crowdstrike__get_alerts` | Check if existing detections already fired for entities discovered during hunt |
| `mcp__crowdstrike__alert_analysis` | Deep dive on a specific alert found during correlation |

### Host Context
| MCP Tool | Purpose |
|----------|---------|
| `mcp__crowdstrike__host_lookup` | Device posture: OS, containment status, policies, agent version |
| `mcp__crowdstrike__host_login_history` | Recent logins on a device (local, remote, interactive) |
| `mcp__crowdstrike__host_network_history` | IP changes, VPN connections, network interface history |

### Cloud Context
| MCP Tool | Purpose |
|----------|---------|
| `mcp__crowdstrike__cloud_query_assets` | Look up cloud resource by resource_id — config, exposure, tags |
| `mcp__crowdstrike__cloud_get_iom_detections` | CSPM compliance evaluations with MITRE, CIS, NIST mapping |
| `mcp__crowdstrike__cloud_get_risks` | Cloud risks ranked by score — misconfigs, unused identities |

### Escalation (confirmed active compromise only)
| MCP Tool | Purpose |
|----------|---------|
| `mcp__crowdstrike__case_create` | Create case for confirmed threat |
| `mcp__crowdstrike__case_add_event_evidence` | Attach hunt findings as evidence |
| `mcp__crowdstrike__case_add_tags` | Tag case for classification and routing |

### Local Tools
| Tool | Purpose |
|------|---------|
| File tools (Read, Grep, Glob) | Read detection templates, search for MITRE mappings, read memory files |

## Key CQL Hunting Patterns

Beyond `cql-patterns` and `logscale-security-queries`, these patterns are specific to hunting:

### Stacking (Long-Tail Analysis)
Find rare values — the workhorse hunting technique:
```cql
// Stack by attribute, sort ascending to surface outliers at the bottom
groupBy([field], function=count()) | sort(_count, order=asc) | tail(50)

// Multi-attribute stacking — catches malware with legitimate names in suspicious paths
groupBy([ServiceName, ServicePath], function=count()) | sort(_count, order=asc) | tail(50)
```

### Temporal Clustering
Detect bursts of activity in time windows:
```cql
bucket(span=5m)
| groupBy([_bucket, user.email], function=count())
| where(_count > 20)
```

### Cross-Source Correlation
Same entity across multiple repos in the same time window:
```cql
// Query 1: Find suspicious IP in CloudTrail
(#repo="cloudtrail" OR #repo="fcs_csp_events") source.ip="<suspicious_ip>"
| groupBy([event.action, Vendor.userIdentity.arn])

// Query 2: Same IP in EntraID sign-in logs
(#repo="microsoft_graphapi" OR #repo="3pi_microsoft_entra_id" OR #repo="fcs_csp_events")
#event.dataset=/entraid/ source.ip="<suspicious_ip>"
| groupBy([user.email, #event.outcome])
```

### Process Tree Reconstruction
Parent-child PID chaining for endpoint telemetry:
```cql
#event_simpleName=ProcessRollup2 aid=<device_id>
| ParentProcessId=<target_pid> OR TargetProcessId=<target_pid>
| table([@timestamp, FileName, CommandLine, ParentBaseFileName, TargetProcessId, ParentProcessId])
| sort(@timestamp, order=asc)
```

### Beacon Detection
Periodic callback patterns via time-delta analysis:
```cql
#event_simpleName=DnsRequest aid=<device_id>
| DomainName=<suspect_domain>
| sort(@timestamp, order=asc)
| timeDelta(@timestamp, as=delta_ms)
| stats([avg(delta_ms, as=avg_interval), stddev(delta_ms, as=jitter), count()])
// Low jitter + regular interval = likely beacon
```
```

- [ ] **Step 2: Verify frontmatter parses correctly**

Run: `head -5 .claude/skills/threat-hunting/SKILL.md`

Expected:
```
---
name: threat-hunting
description: Autonomous threat hunting using the PEAK framework...
---
```

- [ ] **Step 3: Commit**

```bash
git add .claude/skills/threat-hunting/SKILL.md
git commit -m "feat: add threat-hunting SKILL.md — persona, tools, CQL patterns"
```

---

### Task 5: SKILL.md — phase dispatcher, context loading, and Prepare phase

**Files:**
- Modify: `.claude/skills/threat-hunting/SKILL.md` (append after the beacon detection CQL block)

- [ ] **Step 1: Append phase dispatcher, context loading, and Prepare phase**

Append to `.claude/skills/threat-hunting/SKILL.md` after the last line:

```markdown

## Phase Dispatcher

Route based on invocation:

| Command | Action |
|---------|--------|
| `/hunt hypothesis "<statement>"` | Full PEAK cycle — hypothesis-driven hunt |
| `/hunt intel "<context>"` | Full PEAK cycle — intelligence-driven hunt |
| `/hunt baseline "<entity>"` | Full PEAK cycle — baseline/anomaly hunt |
| `/hunt` | Read coverage map, suggest high-value hunt targets |
| `/hunt log` | Display hunt log summary |
| `/hunt coverage` | Display ATT&CK coverage map with gap analysis |

## Context Loading

Load at skill invocation (all hunt types):

1. Read `memory/hunt-log.md` — what hunts have been completed
2. Read `memory/coverage-map.md` — ATT&CK technique coverage and gaps
3. Read `.claude/skills/soc/environmental-context.md` — org baselines, known accounts, infrastructure
4. Read `.claude/skills/soc/memory/investigation-techniques.md` — repo mappings, field gotchas

Load during Prepare phase:
5. Scan `resources/detections/` for `mitre_attack` fields — existing automated detection coverage
6. Check `resources/saved_searches/hunting/` — existing hunting queries that may be relevant

Sub-skills loaded on demand:
- `logscale-security-queries` — when writing CQL queries
- `cql-patterns` — when designing detection backlog entries
- `behavioral-detections` — when proposing correlation-based detections

---

## Prepare Phase

Scope the hunt before running any queries. This phase runs autonomously.

### All Hunt Types

1. **Identify ATT&CK techniques** — map the hunt objective to specific MITRE ATT&CK technique IDs.

2. **Cross-reference detection coverage** — scan `resources/detections/` for templates with matching `mitre_attack` fields. Grep for the technique ID:
   ```bash
   grep -rl "T1234" resources/detections/
   ```
   Note the coverage category:
   - Technique with deployed detections but never hunted = **untested assumption**
   - Technique with no detections AND never hunted = **blind spot**
   - Technique hunted 90+ days ago = **stale coverage**

3. **Check hunt log** — has this technique been hunted before? When? What was found? Avoid redundant work, but re-hunting after 90 days is valid.

4. **Check existing hunting queries** — scan `resources/saved_searches/hunting/` for relevant saved searches. These may provide ready-made CQL for the target technique.

5. **Establish CQL scope filter** — determine which NGSIEM repos to query using the repo mapping table from `investigation-techniques.md`. Validate the data source exists:
   ```cql
   <scope_filter> | count()
   ```
   If 0 results, the data source may not be ingested. Log the gap.

6. **Define time range** — 7 days default for hypothesis and intel hunts. 30 days for baseline hunts. Adjust based on data volume.

7. **Define success/failure criteria** — what evidence would confirm or refute? What constitutes a meaningful anomaly?

### Hypothesis-Driven Additions

- Parse the hypothesis into testable components. A good hypothesis is narrow enough to prove or disprove within bounded effort.
- Identify the specific event types and fields needed to test each component.
- If required data sources are missing, log the gap and either:
  - Pivot to what's available (test a related hypothesis against available data)
  - Abort early with a gap report if the hunt is fundamentally blocked

### Intelligence-Driven Additions

- Extract IOCs from the provided intel: IP addresses, domains, file hashes, user agents, tool names.
- Extract TTPs: what techniques and procedures does the intel describe?
- **Pyramid of Pain escalation plan:** start with IOC sweeps (quick wins), then escalate to TTP hunting (durable value). Map each TTP to CQL-queryable telemetry.
- If the intel references specific threat actors, note their known TTPs for broader behavioral hunting.

### Baseline Additions

- Identify the entity/behavior class: scheduled tasks, services, autorun entries, user-agent strings, DNS queries, process names, network connections.
- Determine stacking attributes — what to `groupBy()` and what to `count()`. Choose attribute groupings carefully: stacking only on name misses malware with legitimate names in suspicious paths. Combine name + path + host.
- Establish time window: 7 days minimum, 30 days preferred for stable environments.
- Rule of thumb: any single stack review should take no more than 10 minutes of analysis. If results are overwhelming, narrow context.
```

- [ ] **Step 2: Verify the section was appended correctly**

Run: `grep -n "## Prepare Phase" .claude/skills/threat-hunting/SKILL.md`

Expected: One match, at a line number after the CQL patterns section.

- [ ] **Step 3: Commit**

```bash
git add .claude/skills/threat-hunting/SKILL.md
git commit -m "feat: add phase dispatcher, context loading, and Prepare phase to SKILL.md"
```

---

### Task 6: SKILL.md — Execute phase

**Files:**
- Modify: `.claude/skills/threat-hunting/SKILL.md` (append after the Baseline Additions section)

- [ ] **Step 1: Append Execute phase**

Append to `.claude/skills/threat-hunting/SKILL.md` after the last line:

```markdown

---

## Execute Phase

Fluid and exploratory. Follow leads, pivot, adapt. Document the investigation chain as you go — this narrative feeds the hunt report.

### Hypothesis-Driven Execution

1. **Run primary hypothesis test queries** — direct CQL queries against the scoped data sources and time range.
2. **Analyze results:**
   - Results support the hypothesis → dig deeper. What's the scope? Which systems/users are affected?
   - Results refute the hypothesis → attempt alternative detection angles for the same TTP. Different event types, different fields, different time windows.
   - Inconclusive → broaden scope or pivot to adjacent techniques.
3. **Pivot on leads** — when an interesting entity (user, IP, host) surfaces:
   - Cross-correlate across data sources (CloudTrail + EntraID + endpoint + DNS)
   - Alert correlation: `get_alerts` for the entity — have existing detections already fired?
   - Pull host/cloud context for interesting endpoints or resources
4. **Document evidence chain** — record each query, what it found, and why you pivoted. This becomes the Findings section of the hunt report.

### Intelligence-Driven Execution

1. **IOC sweep** — search for known indicators across all relevant repos. Fast, concrete results.
   ```cql
   // Example: sweep for suspicious IP across all data sources
   source.ip="<ioc_ip>" OR destination.ip="<ioc_ip>"
   | groupBy([#repo, event.action, source.ip, destination.ip], function=count())
   ```
2. **Pivot from IOC hits** — if any IOC matches:
   - What else did that actor/IP/hash do? Expand the query to all activity from that entity.
   - Timeline analysis: what happened in the 30 minutes before and after the IOC match?
   - Scope assessment: how many systems/users are affected?
3. **TTP hunting (even without IOC matches)** — IOCs rotate trivially; behaviors persist.
   - Hunt for the behavioral patterns described in the intel regardless of IOC results.
   - Use process tree analysis, login correlation, network pattern analysis.
   - This is where durable detection value lives.
4. **Cross-correlate across data sources** — adversaries don't stay in one log source. Check the repo mapping table and query every relevant source for the entities under investigation.

### Baseline Execution

1. **Run stacking queries** — frequency counts across the target attribute grouping.
   ```cql
   // Example: stack scheduled tasks across all Windows endpoints
   #event_simpleName=ScheduledTaskRegistered
   | groupBy([TaskName, TaskExecCommand], function=[count(), collect(ComputerName)])
   | sort(_count, order=asc)
   | tail(50)
   ```
2. **Identify statistical outliers:**
   - Entities on only 1-2 systems (vs. hundreds) — investigate.
   - Unusual values — names that don't fit the pattern, paths in unexpected locations.
   - Low-frequency entries at the tail of the distribution.
3. **Investigate outliers** — for each outlier:
   - Context queries: host lookup, user lookup, process tree reconstruction.
   - Environmental context check: is this a known application, service account, or infrastructure component?
   - If anomalous AND unexplained → potential finding. Document it.
4. **Establish baseline documentation** — record what "normal" looks like. This is valuable even if no threats are found — it informs future hunts and detection tuning.

### Threat Escalation Interrupt

Applies to all hunt types. Two tiers based on "does this need containment?":

**Suspected threat** — interesting but not confirmed:
- Flag the finding in your investigation notes.
- **Continue hunting** to establish scope and gather more evidence.
- Present in the hunt report findings section.
- Do NOT stop the hunt.

**Confirmed active compromise** — evidence of C2, data exfiltration, or lateral movement in progress:
- **STOP the hunt immediately.**
- Produce an escalation package:

```markdown
## ESCALATION: Active Threat Discovered During Hunt

**Hunt**: <title>
**Discovery Time**: <timestamp>
**Threat Type**: <C2 | Exfiltration | Lateral Movement | Other>

### Evidence
<What was found — specific IOCs and timestamps>

### Affected Systems
| System | Type | Evidence |
|--------|------|----------|

### IOCs
| Indicator | Type | Context |
|-----------|------|---------|

### Immediate Risk Assessment
<Is this ongoing? Blast radius? Next likely adversary action?>

### Recommended Immediate Actions
1. <Containment action>
2. <Investigation action>
3. <Communication action>
```

- Create a handoff doc at `docs/handoffs/YYYY-MM-DD-threat-hunting-to-soc-escalation.md`:

```yaml
source_skill: threat-hunting
target_skill: soc
objective: "Incident response for active threat discovered during hunt"
context:
  hunt_title: "<title>"
  threat_type: "<C2 | Exfiltration | Lateral Movement>"
  discovery_time: "<timestamp>"
  affected_systems: [<list>]
  iocs: [<list>]
decisions_made:
  - "Active threat confirmed during hunt — escalation required"
  - "Hunt paused at escalation point"
constraints:
  - "Time-sensitive — containment actions needed"
artifacts:
  - "docs/hunts/YYYY-MM-DD-<slug>.md"
```

- Create a case: `case_create` → `case_add_event_evidence` → `case_add_tags(tags=["true_positive", "hunt_escalation", "<mitre_tactic>"])`
- **Surface to human** — this is the primary human-in-the-loop touchpoint.
- The hunt report is still produced (Act phase) with findings up to the escalation point.
```

- [ ] **Step 2: Verify section appended correctly**

Run: `grep -n "## Execute Phase" .claude/skills/threat-hunting/SKILL.md`

Expected: One match, at a line number after the Prepare phase.

- [ ] **Step 3: Commit**

```bash
git add .claude/skills/threat-hunting/SKILL.md
git commit -m "feat: add Execute phase to SKILL.md — three hunt types + escalation"
```

---

### Task 7: SKILL.md — Act phase

**Files:**
- Modify: `.claude/skills/threat-hunting/SKILL.md` (append after the escalation section)

- [ ] **Step 1: Append Act phase**

Append to `.claude/skills/threat-hunting/SKILL.md` after the last line:

```markdown

---

## Act Phase

Produce all outputs after Execute completes. Runs autonomously.

### 1. Hunt Report

Write the hunt report to `docs/hunts/YYYY-MM-DD-<slug>.md`. This directory is committed to git — hunt reports are permanent archival records.

```markdown
## Hunt Report: <title>
**Date**: YYYY-MM-DD
**Type**: Hypothesis | Intelligence | Baseline
**ATT&CK Techniques**: T1234, T5678
**Duration**: <approximate>
**Outcome**: Threat Found | No Threat — Coverage Validated | Inconclusive

### Hypothesis / Objective
<What we were looking for and why>

### Scope
- **Data sources**: <repos queried>
- **Time range**: <start — end>
- **Entities**: <users, hosts, IPs, services examined>

### Findings
<Chronological investigation narrative — what was queried, what was found, what pivots were taken. Include CQL queries that produced significant results.>

### IOCs
| Indicator | Type | Context |
|-----------|------|---------|
<Only if threat discovered. Omit this section for clean hunts.>

### Conclusion
<2-3 sentences: what did we learn?>

### Self-Evaluation
- **Hypothesis quality**: <Was it testable? Too broad? Too narrow?>
- **Data sufficiency**: <Did we have what we needed? What was missing?>
- **Investigation efficiency**: <Dead ends? Better paths in hindsight?>
- **Suggested next hunt**: <Based on gaps found or leads not fully pursued>
```

### 2. Detection Backlog

Produced when the hunt reveals patterns that could be automated as detections. Include even for clean hunts — baseline knowledge often surfaces detectable patterns.

Present the backlog in the hunt report, then write individual handoff docs:

```markdown
## Proposed Detections from Hunt: <title>

| # | Detection | ATT&CK | Approach | Complexity | Target Skill | Priority |
|---|-----------|--------|----------|------------|-------------|----------|
| 1 | <description> | T1234 | <threshold / stacking / correlation> | <Low / Medium / High> | <behavioral-detections / cql-patterns / logscale-security-queries> | <High / Medium / Low> |
```

For each proposed detection, write a handoff doc to `docs/handoffs/YYYY-MM-DD-threat-hunting-to-<target-skill>-<slug>.md`:

```yaml
source_skill: threat-hunting
target_skill: behavioral-detections | cql-patterns | logscale-security-queries
objective: "Author a detection for [pattern discovered during hunt]"
context:
  hunt_title: "<title>"
  hunt_date: "YYYY-MM-DD"
  threat_scenario: "<what the detection should find>"
  mitre_technique: "<technique ID>"
  mitre_tactic: "<tactic>"
  detection_approach: "<simple threshold | stacking anomaly | behavioral correlation>"
  key_event_types: [<event types observed during hunt>]
  key_fields: [<fields used in hunt queries>]
  volume_notes: "<signal volume and noise characteristics from hunt data>"
  sample_query: "<CQL query from the hunt that surfaced this pattern>"
decisions_made:
  - "Pattern discovered during [hunt type] hunt"
  - "<context about why this detection matters>"
constraints:
  - "120s query timeout"
  - "<data source limitations noted during hunt>"
artifacts:
  - "docs/hunts/YYYY-MM-DD-<slug>.md"
```

If no detectable patterns were found, skip the backlog — not every hunt produces detection opportunities.

### 3. Gap Report

Produced when the hunt identified visibility gaps. Append to the hunt report:

```markdown
## Visibility Gap Report

### Gaps Identified
| Gap | Impact | ATT&CK Techniques Affected | Recommendation |
|-----|--------|---------------------------|----------------|
| <missing data source or field> | <what can't be detected> | T1234, T5678 | <onboard source / enable logging / add field> |

### ATT&CK Coverage Delta
<Techniques that were in scope but couldn't be tested, with reasons>
```

If no gaps were identified, note that all required data was available — this is valuable coverage validation.

### 4. Update Living Documents

After producing all outputs:

**Hunt log** — append one row to `memory/hunt-log.md`:

```
| YYYY-MM-DD | <Type> | <Title> | T1234, T5678 | <Outcome> | <N detections proposed> |
```

**Coverage map** — update `memory/coverage-map.md`:
- Add or update entries in **Hunted** for techniques covered by this hunt.
- Add entries to **Known Gaps** for visibility gaps discovered.
- Regenerate **Suggested Priority Hunts** based on:
  - **Blind spots** — techniques with no detections AND no hunting (scan `resources/detections/` for `mitre_attack` fields, compare against Hunted table)
  - **Untested assumptions** — techniques with deployed detections but not in the Hunted table
  - **Stale coverage** — techniques in Hunted with Last Hunted date 90+ days ago

### 5. Suggest Next Hunt

Based on the self-evaluation, coverage map, and findings, recommend what to hunt next:

- Leads that weren't fully pursued during this hunt
- Adjacent ATT&CK techniques revealed by findings
- High-priority gaps from the updated coverage map
- Techniques whose detections were validated but could be tested with different data sources

Present as: "Based on this hunt, consider hunting next: **<suggestion>** — <rationale>."
```

- [ ] **Step 2: Verify section appended correctly**

Run: `grep -n "## Act Phase" .claude/skills/threat-hunting/SKILL.md`

Expected: One match, at a line number after the Execute phase.

- [ ] **Step 3: Commit**

```bash
git add .claude/skills/threat-hunting/SKILL.md
git commit -m "feat: add Act phase to SKILL.md — outputs, living docs, next-hunt suggestions"
```

---

### Task 8: SKILL.md — utility modes

**Files:**
- Modify: `.claude/skills/threat-hunting/SKILL.md` (append after the Act phase)

- [ ] **Step 1: Append utility modes**

Append to `.claude/skills/threat-hunting/SKILL.md` after the last line:

```markdown

---

## Utility Modes

### `/hunt` (no arguments) — Agent-Suggested Hunting

When invoked without arguments, analyze coverage and suggest high-value hunt targets:

1. Read `memory/coverage-map.md` and `memory/hunt-log.md`.
2. Scan `resources/detections/` for `mitre_attack` fields to build detection coverage picture.
3. Cross-reference to surface three categories:

   | Category | Definition | Priority |
   |----------|-----------|----------|
   | **Blind spots** | No detections AND never hunted | Highest |
   | **Untested assumptions** | Detections deployed but never hunted | High |
   | **Stale coverage** | Last hunted 90+ days ago | Medium |

4. Present the top 3-5 recommended hunts:
   ```
   ## Suggested Hunts

   | # | Technique | Tactic | Category | Suggested Type | Draft Hypothesis |
   |---|-----------|--------|----------|---------------|-----------------|
   | 1 | T1078 Valid Accounts | Defense Evasion | Untested — 3 detections, never hunted | Baseline | Stack authentication patterns across EntraID |
   ```

5. Wait for user to select, then proceed through Prepare → Execute → Act.

### `/hunt log` — Display Hunt Log

Read and present `memory/hunt-log.md` with summary statistics:
- Total hunts completed
- Breakdown by type (hypothesis / intelligence / baseline)
- Breakdown by outcome (threat found / coverage validated / inconclusive)
- Total detections proposed across all hunts
- Most recently hunted ATT&CK techniques

### `/hunt coverage` — Display Coverage Map

Read `memory/coverage-map.md` and cross-reference with `resources/detections/`:
- **Hunted techniques** with last hunt date, result, and data quality
- **Known gaps** with impact and recommendations
- **Detection coverage overlay** — for each hunted technique, note whether automated detections exist
- **Suggested priority hunts** with rationale
```

- [ ] **Step 2: Verify full SKILL.md structure**

Run: `grep -n "^## " .claude/skills/threat-hunting/SKILL.md`

Expected output showing all major sections in order:
```
## Persona & Principles
## Available Tools
## Key CQL Hunting Patterns
## Phase Dispatcher
## Context Loading
## Prepare Phase
## Execute Phase
## Act Phase
## Utility Modes
```

- [ ] **Step 3: Check total line count**

Run: `wc -l .claude/skills/threat-hunting/SKILL.md`

Expected: approximately 400-500 lines.

- [ ] **Step 4: Commit**

```bash
git add .claude/skills/threat-hunting/SKILL.md
git commit -m "feat: add utility modes to SKILL.md — /hunt, /hunt log, /hunt coverage"
```

---

### Task 9: /hunt command router

**Files:**
- Create: `.claude/commands/hunt.md`

- [ ] **Step 1: Write the /hunt command file**

Write `.claude/commands/hunt.md`:

```xml
<command name="hunt">
    <description>Threat hunting: $ARGUMENTS</description>

    <rules priority="critical">
        <rule>Always invoke the threat-hunting skill for processing</rule>
        <rule>Update .claude/skills/threat-hunting/memory/ files after every completed hunt per the Living Documents protocol</rule>
        <rule>Escalate immediately on confirmed active compromise — create case, handoff doc, surface to human</rule>
        <rule>Produce all three outputs (hunt report, detection backlog, gap report) in the Act phase</rule>
        <rule>Never modify detection templates directly — produce handoff docs for authoring skills</rule>
    </rules>

    <actions>
        <action trigger="starts-with:hypothesis">
            Run a hypothesis-driven threat hunt. Follow the threat-hunting skill PEAK workflow (Prepare → Execute → Act).
        </action>

        <action trigger="starts-with:intel">
            Run an intelligence-driven threat hunt. Follow the threat-hunting skill PEAK workflow (Prepare → Execute → Act).
        </action>

        <action trigger="starts-with:baseline">
            Run a baseline/anomaly threat hunt. Follow the threat-hunting skill PEAK workflow (Prepare → Execute → Act).
        </action>

        <action trigger="starts-with:log">
            Display the hunt log. Read and summarize .claude/skills/threat-hunting/memory/hunt-log.md.
        </action>

        <action trigger="starts-with:coverage">
            Display the ATT&amp;CK coverage map. Read .claude/skills/threat-hunting/memory/coverage-map.md and cross-reference with resources/detections/.
        </action>

        <action trigger="default">
            No hunt type specified. Read the coverage map and suggest high-value hunt targets.
            If no arguments at all, follow the /hunt (no arguments) utility mode in the threat-hunting skill.
            If arguments don't match a known subcommand, treat as a hypothesis and route to hypothesis-driven hunting.
        </action>
    </actions>
</command>
```

- [ ] **Step 2: Verify command file structure matches existing commands**

Run: `diff <(grep -o '<[^>]*>' .claude/commands/soc.md | sort -u) <(grep -o '<[^>]*>' .claude/commands/hunt.md | sort -u)`

Expected: Same XML elements used in both files (command, description, rules, rule, actions, action).

- [ ] **Step 3: Commit**

```bash
git add .claude/commands/hunt.md
git commit -m "feat: add /hunt command router"
```

---

### Task 10: Update CLAUDE.md with threat-hunting skill

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Add threat-hunting to the Available Skills table**

In `CLAUDE.md`, find the skills table:

```markdown
| `detection-tuning` | FP tuning patterns with enrichment function catalog | Stable |
```

Add after the last skill row:

```markdown
| `threat-hunting` | Autonomous PEAK-based threat hunting — hypothesis, intel, baseline hunts | Experimental |
```

- [ ] **Step 2: Add /hunt to the Commands table**

In `CLAUDE.md`, find the commands table:

```markdown
| `/discuss` | Exploratory discussion mode (read-only, no changes) |
```

Add after:

```markdown
| `/hunt` | Autonomous threat hunting — hypothesis, intel, baseline, coverage analysis |
```

- [ ] **Step 3: Add hunt subcommands section**

In `CLAUDE.md`, find the SOC Subcommands section. Add after it:

```markdown
### Hunt Subcommands

```
/hunt hypothesis "<statement>"   — Hypothesis-driven hunt
/hunt intel "<context>"          — Intelligence-driven hunt
/hunt baseline "<entity>"        — Baseline/anomaly hunt
/hunt                            — Suggest hunts from coverage gaps
/hunt log                        — View hunt history
/hunt coverage                   — View ATT&CK hunt coverage map
```
```

- [ ] **Step 4: Verify CLAUDE.md changes**

Run: `grep -A1 "threat-hunting" CLAUDE.md`

Expected: The skill table row and command table row are visible.

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: add threat-hunting skill and /hunt command to CLAUDE.md"
```

---

## Self-Review

### Spec Coverage Check

| Spec Section | Implementing Task |
|---|---|
| Skill Identity (name, location, persona) | Task 4 — frontmatter + persona |
| Invocation (6 command variants) | Task 5 — phase dispatcher, Task 9 — command router |
| Phase Architecture — Prepare | Task 5 |
| Phase Architecture — Execute | Task 6 |
| Phase Architecture — Act | Task 7 |
| Threat Escalation Interrupt | Task 6 — inline in Execute phase |
| MCP Tools | Task 4 — tool reference tables |
| Key CQL Patterns | Task 4 — 5 hunting-specific patterns |
| Outputs — Hunt Report | Task 7 — template in Act phase |
| Outputs — Detection Backlog | Task 7 — template + handoff doc format |
| Outputs — Gap Report | Task 7 — template in Act phase |
| Living Documents — hunt-log.md | Task 2 |
| Living Documents — coverage-map.md | Task 2 |
| Living Documents — update protocol | Task 7 — Act phase step 4 |
| Self-Evaluation | Task 7 — in hunt report template |
| Suggest Next Hunt | Task 7 — Act phase step 5, Task 8 — /hunt no-args mode |
| Coverage Map Cross-Reference | Task 5 (Prepare), Task 7 (Act), Task 8 (utility modes) |
| Integration — handoff docs | Task 7 — detection backlog handoff format |
| Integration — escalation handoff | Task 6 — escalation interrupt |
| File Structure | Task 1 (scaffold), Task 3 (DESIGN.md) |
| Context Loading Order | Task 5 |
| docs/hunts/ (committed) | Task 1 — .gitkeep |
| docs/handoffs/ (gitignored) | Task 1 — .gitignore |
| CLAUDE.md updates | Task 10 |

All spec sections are covered.

### Placeholder Scan

No TBDs, TODOs, "implement later", or "similar to Task N" found.

### Type/Name Consistency

- `memory/hunt-log.md` — consistent across Tasks 2, 5, 7, 8
- `memory/coverage-map.md` — consistent across Tasks 2, 5, 7, 8
- `environmental-context.md` path — `.claude/skills/soc/environmental-context.md` in Task 5
- `investigation-techniques.md` path — `.claude/skills/soc/memory/investigation-techniques.md` in Task 5
- `resources/detections/` + `mitre_attack` field — consistent across Tasks 5, 7, 8
- `resources/saved_searches/hunting/` — referenced in Task 5 (Prepare)
- `docs/hunts/YYYY-MM-DD-<slug>.md` — consistent across Tasks 1, 6, 7
- `docs/handoffs/YYYY-MM-DD-threat-hunting-to-<skill>-<slug>.md` — consistent across Tasks 6, 7
- Handoff doc field names (`source_skill`, `target_skill`, `objective`, `context`, `decisions_made`, `constraints`, `artifacts`) — consistent with source-threat-modeling spec
- MCP tool names — match exactly what SOC skill SKILL.md uses
- Command name `/hunt` — consistent across Tasks 5, 8, 9, 10
