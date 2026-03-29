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
