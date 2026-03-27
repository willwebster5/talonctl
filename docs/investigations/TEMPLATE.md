# Incident: <Short Title>

**Date:** YYYY-MM-DD
**Analyst:** <who triaged>
**Alert ID(s):** <composite alert ID(s)>
**CrowdStrike Case:** <case ID if created, or "N/A">
**Severity:** P0 / P1 / P2 / P3
**Classification:** True Positive / False Positive / Investigating
**MITRE ATT&CK:** <technique IDs>

## Summary
<2-3 sentences: what happened, what was affected, what the outcome was>

## Timeline
| Time (UTC) | Source | Event |
|------------|--------|-------|
| YYYY-MM-DD HH:MM | <platform> | <what happened> |

## Affected Assets
| Asset | Type | Details |
|-------|------|---------|
| <hostname/account/resource> | <endpoint/cloud resource/identity> | <OS, account ID, etc.> |

## Investigation Evidence

### Alert Payload
<key fields from alert_analysis output>

### NGSIEM Queries Executed
<CQL queries run, with results summary — not raw output>

### MCP Tool Results
<host_lookup, cloud_query_assets, etc. — key findings only>

## Analysis
<what the evidence shows, why it is TP/FP, attack chain reconstruction if TP>

## IOCs
| IOC | Type | Context |
|-----|------|---------|
| <value> | IP / domain / hash / email | <where observed, confidence level> |

## Containment Actions Taken
<what was done: host contained, account disabled, rule deployed, etc.>

## Remediation Steps
- [ ] <action item 1>
- [ ] <action item 2>

## Lessons Learned
<tuning decisions, detection gaps identified, process improvements>
