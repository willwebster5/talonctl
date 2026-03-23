<!-- PHASE: Triage (Phase 2)
     LOADED BY: /soc triage
     PURPOSE: Query patterns, field gotchas, data source mappings, and API quirks.
     Loaded BEFORE running any investigation queries.
     UPDATE: Add new query patterns, field discoveries, and API behavior notes. -->

# Investigation Techniques

Reference loaded at Phase 2 (triage) before running investigation queries.

## Data Source → NGSIEM Repository Mapping

**Always consult this table before writing queries.** Using the wrong repo returns 0 results silently.

| Platform | NGSIEM Repo | Source Filter | Notes |
|----------|------------|---------------|-------|
<!-- Add your platform-to-repo mappings here. Example:
| AWS CloudTrail | `cloudtrail` + `fcs_csp_events` | `(#repo="cloudtrail" OR #repo="fcs_csp_events") #Vendor="aws" #repo!="xdr*"` | Both repos carry CloudTrail events |
-->

## Field Gotchas

Known field name traps that cause silent query failures or wrong results:

| Field | Gotcha | Correct Usage |
|-------|--------|---------------|
<!-- Add your field gotchas here. Example:
| `event_simpleName` | Requires `#` prefix (tagged field) | `#event_simpleName=DnsRequest` not `event_simpleName=DnsRequest` |
-->

## Investigation Principles

<!-- Add your investigation principles here. Examples: cross-source correlation, temporal analysis, process genealogy, cloud asset verification. -->

## API & Tool Quirks

<!-- Add API behavior notes and known issues here. -->

## Useful Hunting Queries

<!-- Add your verified CQL hunting query templates here. Use {{placeholder}} for substitution values. -->
