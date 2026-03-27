---
description: Structured review workflow for OOTB detection templates in templates_review/
allowed-tools: Bash, Read, Write, Edit, Grep, Glob, mcp__crowdstrike__ngsiem_query
---

# Template Review Workflow

You are reviewing OOTB CrowdStrike detection templates for promotion or rejection.

## Command Modes

- No arguments: pick the next unreviewed template (check `.review_log.yaml` for already-reviewed)
- `<vendor>`: review templates for a specific vendor (microsoft, crowdstrike, aws, akamai, cisco, authentik)
- `--stats`: show review progress by vendor

## Per-Template Review Steps

For each template, follow these 6 steps in order:

### Step 1: Read and Classify

1. Load the template YAML from `templates_review/<vendor>/`
2. Identify: data source requirements, MITRE mapping, detection logic type
3. Check data source availability:
   - Microsoft Windows event logs via HEC: verify with `#Vendor="microsoft" #event.module="windows" | count()` (30d)
   - Microsoft Defender 365: verify with `#Vendor="microsoft" #event.module="windows-defender-365" | count()` (30d)
   - Microsoft M365: verify with `#Vendor="microsoft" #event.module="m365" | count()` (30d)
   - CrowdStrike Identity: verify with `#repo="xdr_indicatorsrepo" #event.module="identity-protection" | count()` (30d)
   - Akamai: verify with `#Vendor="akamai" | count()` (30d)
   - Cisco: verify with `#Vendor="cisco" | count()` (30d)
   - Authentik: verify with `#Vendor="authentik" | count()` (30d)
4. If data source returns 0: REJECT with reason "Data source not ingested"

### Step 2: Duplicate Check

1. Search `resources/detections/` for existing detections covering the same MITRE technique
2. Compare event sources and detection logic
3. Record: `duplicate_of: <resource_id>` or `complements: <resource_id>` or `unique`

### Step 3: 30-Day Baseline

1. Extract `search.filter` from the template
2. Run `| count()` via ngsiem_query (time_range: 30d) for total volume
3. If count > 0, run with `| groupBy([<actor_field>], function=[count(as=Count)]) | sort(Count, order=desc)` to profile actors
4. Record: total hits, top actors, estimated daily volume

### Step 4: Environmental Tuning Assessment

Check available enrichment functions for this vendor:
- Microsoft: 18 EntraID functions available (see `resources/saved_searches/entraid_*.yaml`)
- CrowdStrike: endpoint enrichment functions NOT yet built
- AWS: 9 functions available
- Other vendors: no enrichment functions

Estimate tuning effort: none, light, heavy

### Step 5: Decision

Present the evidence and recommend one of:
- **Promote**: add resource_id, apply enrichment, move to `resources/detections/<vendor>/`
- **Promote (deferred)**: valid but needs enrichment functions built first
- **Reject (no data source)**: data source not ingested
- **Reject (duplicate)**: existing detection covers this TTP
- **Reject (not relevant)**: TTP not applicable to environment

Wait for user confirmation before executing.

### Step 6: Record

Append to `templates_review/.review_log.yaml`:
```yaml
- template_id: <from _template_metadata>
  filename: <vendor/filename.yaml>
  reviewed_date: <today>
  decision: promote | reject
  reason: "<evidence summary>"
  baseline_30d_count: <number>
  tuning_effort: none | light | heavy
  promoted_to: <path if promoted>
  dependencies: []
```

If promoting:
1. Strip `_template_metadata` block
2. Add `resource_id` using naming convention: `<vendor>___<detection_name>`
3. Convert `tactic`/`technique` to `mitre_attack: ["TA####:T####"]` format
4. Add applicable enrichment functions
5. Add analyst-ready table output with risk scoring
6. Set `status: inactive`
7. Add `dependencies:` for referenced saved searches
8. Move to `resources/detections/<vendor>/`
9. Delete from `templates_review/<vendor>/`

If rejecting:
1. Create `templates_review/_rejected/` if it does not exist
2. Move file to `templates_review/_rejected/<vendor>___<filename>`
3. Delete from `templates_review/<vendor>/`

## Stats Mode

When `--stats` is passed, read `.review_log.yaml` and show:
```
Template Review Progress:
  Microsoft:   X/52 reviewed  (Y promoted, Z rejected)
  CrowdStrike: X/12 reviewed  (Y promoted, Z rejected)
  AWS:         X/7 reviewed   (Y promoted, Z rejected)
  Akamai:      X/2 reviewed   (Y promoted, Z rejected)
  Cisco:       X/1 reviewed   (Y promoted, Z rejected)
  Authentik:   X/1 reviewed   (Y promoted, Z rejected)
  Total:       X/75 reviewed
```
