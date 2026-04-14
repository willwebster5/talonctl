<!-- TIER: L1 (Always)
     LOADED BY: Every session start
     PURPOSE: Compact routing table — fast-track patterns, platform file locations, key baselines.
     KEEP UNDER 150 LINES. This is a routing table, not a knowledge store. -->

# SOC Knowledge Base Index

> Load this file at session start. Detail files are in `knowledge/` — read on demand.
> Last updated: 2026-04-14

## Fast-Track Patterns (close without investigation)

<!-- Add patterns here when ALL three criteria are met:
  1. 100% confidence — no investigation needed
  2. Recurring noise — appears multiple times per week
  3. Never been a TP — historical pattern is always benign

Format:
- <pattern description>: `<matching criteria>` → <action> -->

## Platform Pattern Files

| Platform | File | Last Updated | Active Patterns |
|----------|------|-------------|-----------------|
| AWS | `knowledge/patterns/aws.md` | — | 0 FP, 0 TP |
| EntraID | `knowledge/patterns/entraid.md` | — | 0 FP, 0 TP |
| Google | `knowledge/patterns/google.md` | — | 0 FP, 0 TP |
| CrowdStrike | `knowledge/patterns/crowdstrike.md` | — | 0 FP, 0 TP |
| Network | `knowledge/patterns/network.md` | — | 0 FP, 0 TP |
| Box | `knowledge/patterns/box.md` | — | 0 FP, 0 TP |
| GitHub | `knowledge/patterns/github.md` | — | 0 FP, 0 TP |

## Recent TP Activity

<!-- Add confirmed TPs in reverse chronological order:
- [YYYY-MM-DD] Description (platform) -->

## Tuning Backlog (pending items: 0)

→ See `knowledge/tuning/tuning-backlog.md`

## Key References

- Environmental context: `knowledge/context/environmental-context.md`
- Investigation techniques: `knowledge/techniques/investigation-techniques.md`
- Detection ideas: `knowledge/ideas/detection-ideas.md`
