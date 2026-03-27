# Incident Investigations

Persist investigation findings from confirmed True Positive alerts (SOC skill Phase 3C).

## File Naming

`YYYY-MM-DD_<short-slug>.md`

Example: `2026-03-26_entraid-suspicious-signin-jdoe.md`

## When to Create

- After Phase 3C confirms a True Positive
- After case creation in CrowdStrike
- NOT for false positives (those go in MEMORY.md)

## Template

Use the template below for all incident reports. The SOC skill should auto-generate
this from investigation context gathered in Phases 1-2.

## What NOT to Include

- Raw NGSIEM query output (too large, stale quickly)
- Full alert payloads (available in CrowdStrike console)
- Sensitive credentials or tokens observed during investigation
