# Threat Hunting Skill — Design Spec

An autonomous, agentic threat hunting skill for ClaudeStrike's Agentic SOC. Implements the PEAK framework (Prepare → Execute → Act) across three hunt types with self-evaluation, structured outputs, and integration into the detection lifecycle.

## Problem

ClaudeStrike's current hunting capability is a 6-step subcommand (`/soc hunt`) — user provides IOCs or a hypothesis, agent runs CQL, presents results. No structured preparation, no post-hunt outputs, no feedback loop into detection engineering, no institutional knowledge accumulation across hunts.

The research literature (threat-hunting-research.md) establishes that hunting's compounding value comes from the **hunting → detection engineering pipeline**: every manual discovery encoded as an automated rule permanently improves defenses. Organizations at HM4 maturity systematize this. ClaudeStrike has all the downstream skills (`behavioral-detections`, `cql-patterns`, `detection-tuning`) but no structured upstream hunting practice feeding them.

This skill is an experiment in **agentic threat hunting** — the agent drives the full PEAK lifecycle autonomously, with humans surfaced primarily for threat escalation and final review.

## Scope

A standalone Claude Code skill that:

- Executes structured threat hunts across three types (hypothesis-driven, intelligence-driven, baseline/anomaly)
- Runs autonomously through Prepare → Execute → Act phases with minimal human-in-the-loop
- Produces three outputs: hunt report, detection backlog (with handoff docs), visibility gap report
- Self-evaluates and suggests next hunts based on ATT&CK coverage gaps
- Maintains lightweight living documents (hunt log, coverage map)
- Escalates to the SOC skill when active threats are discovered

## Design Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Relationship to `/soc hunt` | Standalone skill — independent, not a subcommand | Clean separation of concerns. `/soc hunt` remains a quick ad-hoc mode; this skill handles the full PEAK lifecycle. |
| Hunt types | All three: hypothesis, intelligence, baseline | PEAK framework structures them cleanly. CrowdStrike NGSIEM supports all three (CQL handles stacking natively for baseline). |
| Human-in-the-loop | Minimal — agentic execution, escalation is the interrupt | Experiment in autonomous hunting. Humans provide the trigger and review outputs, not gate phases. |
| Outputs | Hunt report + detection backlog + gap report | Full Act phase. Detection backlog closes the feedback loop. Gap report enables HM3/HM4 maturity. |
| Living documents | Lightweight — hunt log + ATT&CK coverage map | Prevents redundant hunts, informs prioritization. Baselines expressed as CQL/detections, not memory files. |
| Threat escalation | Tiered — continue for suspected, hard stop for active compromise | Matches real hunt team operations. "Does this need containment?" is the decision boundary. |
| Phase architecture | PEAK-aligned, fluid execution, no human gates between phases | Hunting is exploratory. Rigid gates fight the nature of the activity. |
| Self-evaluation | Part of Act phase, feeds coverage map and next-hunt suggestions | Embodies HM4 maturity ideal — systematic improvement of the hunting cycle. |

---

## Skill Identity

**Name:** `threat-hunting`
**Location:** `.claude/skills/threat-hunting/`
**Persona:** Autonomous threat hunter operating inside a CrowdStrike NG-SIEM environment. Assumes breach. Follows leads. Produces actionable outputs.

**Sub-skills loaded:** `logscale-security-queries` (CQL reference), `cql-patterns` (query patterns), `behavioral-detections` (correlation patterns for detection backlog output).

---

## Invocation

| Command | Hunt Type | Example |
|---|---|---|
| `/hunt hypothesis "<statement>"` | Hypothesis-driven | `/hunt hypothesis "Adversary may be using DNS tunneling for C2 from production servers"` |
| `/hunt intel "<context>"` | Intelligence-driven | `/hunt intel "CVE-2025-55241 — undocumented Microsoft tokens bypassing MFA"` |
| `/hunt baseline "<entity>"` | Baseline/anomaly | `/hunt baseline "scheduled tasks across all Windows endpoints"` |
| `/hunt` | Agent-suggested | Reads coverage map, suggests high-value targets based on ATT&CK gaps |
| `/hunt log` | Utility | Display hunt log summary |
| `/hunt coverage` | Utility | Display ATT&CK coverage map with gaps |

---

## Phase Architecture

Three PEAK-aligned phases, executed autonomously. No human gates between phases. Human is surfaced only for threat escalation or at hunt completion.

### Prepare Phase

Scopes the hunt before running any queries.

**All hunt types:**
1. Load living docs — `memory/hunt-log.md`, `memory/coverage-map.md`
2. Load `environmental-context.md` for org baselines
3. Load `memory/investigation-techniques.md` for repo mapping and field gotchas
4. Cross-reference `resources/detections/` MITRE mappings to understand existing automated detection coverage for the target techniques
5. Determine ATT&CK technique mapping for the hunt
6. Establish CQL scope filter (repos, time range, entity constraints)
7. Define success/failure criteria — what would confirm or refute?

**Hypothesis-driven additions:**
- Parse the hypothesis into testable components
- Identify required data sources and confirm they exist (quick `ngsiem_query` to validate repo/field availability)
- If data sources are insufficient, log the gap and either pivot to what's available or abort with a gap report

**Intelligence-driven additions:**
- Extract IOCs and TTPs from the provided intel context
- Escalate IOCs to behavioral patterns (Pyramid of Pain — move up from hashes/IPs to TTPs)
- Map TTPs to CQL-queryable telemetry

**Baseline additions:**
- Identify the entity/behavior class to baseline
- Determine the stacking attributes (what to group by, what to count)
- Establish time window for baseline (7-30 days depending on data volume)

### Execute Phase

Fluid, exploratory. The agent follows leads, pivots, and adapts.

**Hypothesis-driven:**
1. Run primary hypothesis test queries
2. Analyze results — does the data support or refute?
3. If leads emerge, pivot: correlate across data sources, expand scope
4. If no leads, attempt alternative detection angles for the same TTP
5. Document evidence chain as investigation progresses

**Intelligence-driven:**
1. Sweep for IOCs first (quick wins)
2. Pivot from any IOC hits to behavioral patterns — what else did that actor/IP/hash do?
3. Hunt for the TTPs described in the intel even without IOC matches (IOCs may have rotated but behavior persists)
4. Cross-correlate across data sources (CloudTrail + EntraID + endpoint + network)

**Baseline:**
1. Run stacking queries — frequency counts across the target attribute
2. Identify statistical outliers (entities appearing on 1-2 systems, unusual values, low-frequency entries)
3. Investigate outliers — context queries to determine if anomalous = malicious
4. Establish documented baseline for future comparison

**Threat escalation interrupt (all types):**
- **Suspected threat:** Continue hunting to establish scope. Flag finding but don't stop.
- **Confirmed active compromise** (C2, exfiltration, active lateral movement): Stop hunting. Produce immediate escalation package with IOCs, affected systems, timeline. Create handoff doc for SOC skill. Surface to human.

### Act Phase

Produce all outputs and self-evaluate.

1. **Hunt Report** — structured findings document (persisted to `docs/hunts/`)
2. **Detection Backlog** — proposed detections with handoff docs to authoring skills
3. **Gap Report** — visibility gaps, missing telemetry, ATT&CK coverage holes
4. **Self-evaluation** — hypothesis quality, data sufficiency, investigation efficiency
5. **Update living docs** — append to hunt log, update coverage map
6. **Suggest next hunt** — based on coverage gaps, findings, and staleness

---

## MCP Tools

| Activity | MCP Tools | Usage Pattern |
|---|---|---|
| Hypothesis testing | `ngsiem_query` | Ad-hoc CQL — the workhorse. Multiple queries per hunt, pivoting between repos. |
| Stacking/baselining | `ngsiem_query` | `groupBy()` + `count()` + `sort()` across large time windows. Long-tail analysis. |
| IOC sweeps | `ngsiem_query` | Multi-repo searches for hashes, IPs, domains across all telemetry. |
| Host context | `host_lookup`, `host_login_history`, `host_network_history` | When an endpoint surfaces during a hunt. |
| Cloud context | `cloud_query_assets`, `cloud_get_risks`, `cloud_get_iom_detections` | When cloud resources or IAM activity surfaces. |
| Alert correlation | `get_alerts`, `alert_analysis` | Check if existing detections already fired for discovered entities. |
| Escalation | `case_create`, `case_add_event_evidence`, `case_add_tags` | Only on confirmed active compromise. |

### Key CQL Patterns

Beyond what `cql-patterns` and `logscale-security-queries` provide, the skill carries knowledge of hunting-specific query patterns:

- **Stacking:** `groupBy([field], function=count()) | sort(_count, order=asc) | tail(50)` — find rare values
- **Temporal clustering:** `bucket(span=5m)` + `groupBy()` — detect bursts of activity
- **Cross-source correlation:** Same entity (user, IP, hostname) across multiple repos within the same time window
- **Process tree reconstruction:** Parent-child PID chaining via `ngsiem_query` against EDR telemetry
- **Beacon detection:** Periodic callback patterns via time-delta analysis on network connections

---

## Outputs

### Hunt Report

Produced after every hunt. Persisted to `docs/hunts/YYYY-MM-DD-<slug>.md`. This directory is committed to git — hunt reports are permanent archival records (unlike `docs/handoffs/` which is gitignored).

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
<Chronological investigation narrative>

### IOCs
| Indicator | Type | Context |
|-----------|------|---------|
<only if threat discovered>

### Conclusion
<2-3 sentences: what did we learn?>

### Self-Evaluation
- **Hypothesis quality**: <Was it testable? Too broad? Too narrow?>
- **Data sufficiency**: <Did we have what we needed?>
- **Investigation efficiency**: <Dead ends? Better paths in hindsight?>
- **Suggested next hunt**: <Based on gaps found or leads not fully pursued>
```

### Detection Backlog

Produced when the hunt reveals detectable patterns.

```markdown
## Proposed Detections from Hunt: <title>

| # | Detection | ATT&CK | Approach | Complexity | Target Skill | Priority |
|---|-----------|--------|----------|------------|-------------|----------|
```

Each entry gets a handoff doc to `docs/handoffs/` following the standard handoff spec:

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
  key_event_types: [...]
  key_fields: [...]
  volume_notes: "<expected signal volume and noise characteristics>"
  sample_query: "<CQL query from the hunt that surfaced this pattern>"
decisions_made:
  - "Pattern discovered during [hunt type] hunt"
  - "<any context about why this detection matters>"
constraints:
  - "120s query timeout"
  - "<any data source limitations noted during hunt>"
artifacts:
  - "docs/hunts/YYYY-MM-DD-<slug>.md"
```

### Gap Report

Documents what the hunter couldn't see.

```markdown
## Visibility Gap Report: <hunt title>

### Gaps Identified
| Gap | Impact | ATT&CK Techniques Affected | Recommendation |
|-----|--------|---------------------------|----------------|

### ATT&CK Coverage Delta
<Techniques in scope but untestable, with reasons>
```

---

## Living Documents

Two files in `.claude/skills/threat-hunting/memory/`.

### `hunt-log.md`

Append-only log of completed hunts. One entry per hunt.

```markdown
# Hunt Log

| Date | Type | Title | ATT&CK | Outcome | Detections Proposed |
|------|------|-------|--------|---------|-------------------|
```

### `coverage-map.md`

ATT&CK technique coverage tracker, updated after every hunt. Tracks the **hunt layer** — what has been proactively hunted. Cross-referenced during Prepare against deployed detection MITRE mappings from `resources/detections/` to identify high-value targets.

```markdown
# ATT&CK Hunt Coverage Map

## Hunted
| Technique | Tactic | Last Hunted | Result | Data Quality |
|-----------|--------|-------------|--------|-------------|

## Known Gaps
| Technique | Tactic | Reason | Recommendation |
|-----------|--------|--------|----------------|

## Suggested Priority Hunts
<Auto-generated from: gaps, staleness (90+ days since last hunt), techniques with detections but no hunting validation>
```

The coverage map tracks techniques the skill has engaged with or identified as gaps. It grows organically through use. During Prepare, the skill cross-references this against deployed detection MITRE mappings to surface three categories of high-value hunt targets:

1. **Blind spots** — techniques with no detections AND no hunting (highest priority)
2. **Untested assumptions** — techniques with deployed detections but never hunted (are the detections actually catching things?)
3. **Stale coverage** — techniques hunted 90+ days ago (the environment may have changed)

---

## Integration & Handoffs

### Upstream Triggers

| Source | How | Example |
|---|---|---|
| Human | Direct invocation via `/hunt` | "Hunt for lateral movement in the cloud accounts" |
| Coverage map | Agent suggests when invoked with no args | "T1078 Valid Accounts hasn't been hunted and has 3 detections — worth validating" |
| Source-threat-modeling | Handoff doc — threat scenarios not yet hunted | "Okta session hijacking was modeled but never validated against live data" |
| SOC skill | Finding during triage warrants deeper investigation | Analyst spots suspicious pattern, spins up a hunt |
| External intel | User provides CVE, campaign report, ISAC advisory | "CrowdStrike blog on SCATTERED SPIDER new TTPs" |

### Downstream Outputs

| Output | Target | Mechanism |
|---|---|---|
| Detection backlog entries | `behavioral-detections`, `cql-patterns`, `logscale-security-queries` | Handoff docs to `docs/handoffs/` |
| Escalation package | SOC skill (`/soc`) | Handoff doc with IOCs, timeline, affected systems |
| Gap report | `source-threat-modeling` | Visibility gaps feed back into detection planning |
| Hunt report | `docs/hunts/` | Persistent record (archival, not a handoff) |
| Living doc updates | Own `memory/` | Hunt log + coverage map |

### Handoff Doc Format

Same spec as source-threat-modeling and response-playbooks. Standard fields: `source_skill`, `target_skill`, `objective`, `context`, `decisions_made`, `constraints`, `artifacts`.

### Relationship to Deployed Detection Coverage

During Prepare, the skill reads MITRE mappings from `resources/detections/` to understand existing automated detection coverage. This informs hunt prioritization but the skill never modifies detection files directly. Detection authoring is always delegated via handoff docs.

---

## File Structure

```
.claude/skills/threat-hunting/
├── SKILL.md                    # Main skill definition
├── DESIGN.md                   # Architecture rationale
└── memory/
    ├── hunt-log.md             # Completed hunts log
    └── coverage-map.md         # ATT&CK hunt coverage tracker

.claude/commands/
└── hunt.md                     # /hunt command routing to skill
```

### Context Loading at Invocation

1. `SKILL.md` (always)
2. `memory/hunt-log.md` (always — what's been done)
3. `memory/coverage-map.md` (always — informs prioritization)
4. `environmental-context.md` (always — org baselines)
5. `memory/investigation-techniques.md` (Prepare phase — repo mappings, field gotchas)
6. Sub-skills on demand: `logscale-security-queries`, `cql-patterns`, `behavioral-detections`

---

## What's NOT In Scope

- **Replacing `/soc hunt`** — the SOC skill's hunt mode stays as a quick ad-hoc option. This skill is the full PEAK lifecycle.
- **Detection authoring** — delegated to existing skills via handoff docs. The skill proposes detections, it doesn't write CQL or YAML.
- **Incident response** — on active compromise, the skill produces an escalation package and hands off to the SOC skill. It doesn't contain or remediate.
- **UEBA/ML** — the skill uses CQL-native stacking and statistical analysis for baseline hunts. It doesn't integrate external ML models or UEBA platforms.
- **Campaign orchestration** — each invocation is a single hunt. Multi-hunt campaigns can be layered on later if single hunts prove effective.

## Relationship to Existing Skills

```
                         threat-hunting (NEW)
                         "what's hiding"
                              |
              +---------------+---------------+
              |               |               |
       hunt report    detection backlog    gap report
              |               |               |
         docs/hunts/    handoff docs     feeds back to
         (archival)          |          source-threat-modeling
                             |
               +-------------+-------------+
               |             |             |
        behavioral-    cql-patterns   logscale-security-
        detections    "how to write"   queries
        "how to write"                "how to write"
               |             |             |
               +------+------+------+------+
                      |             |
               detection-tuning  response-playbooks
               "how to tune"    "what response"
```

## Research Foundation

This skill's design is grounded in the threat hunting research survey (`/home/will/projects/agent-skills/threat-hunting-research.md`). Key concepts incorporated:

- **PEAK framework** (Bianco et al., 2023) — Prepare → Execute → Act phase structure
- **Hunting Maturity Model** — targeting HM4 (systematic automation of hunting discoveries into detections)
- **Pyramid of Pain** (Bianco, 2013) — intelligence-driven hunts escalate from IOCs to TTPs
- **Stacking/long-tail analysis** — core technique for baseline hunts
- **Hunt → detection engineering feedback loop** — the detection backlog output systematizes this
- **"A hunt that finds no threats is not a failure"** — the gap report and coverage validation capture value from clean hunts
- **Self-evaluation** — Approach 3 element enabling continuous improvement of the hunting practice
