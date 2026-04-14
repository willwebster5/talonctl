<!-- TIER: L2
     LOADED BY: Phase 2 (Triage investigation)
     PURPOSE: Query patterns, field gotchas, NGSIEM repo mapping table.
     UPDATE: When new investigation techniques are discovered or field behaviors change. -->

# Investigation Techniques

Query patterns and field reference for NGSIEM investigations. Loaded at Phase 2 before running investigation queries.

## NGSIEM Repo Mapping

<!-- Map data sources to NGSIEM repos:

| Data Source | Repo Filter | Key Fields |
|---|---|---|
| AWS CloudTrail | `#repo=cloudtrail` | `aws.accountId`, `userIdentity.arn` |
| EntraID Audit | `#repo=entraid_audit` | `user.userPrincipalName` |
-->

## Field Gotchas

<!-- Document fields that behave unexpectedly:

### Field Name
- **Issue:** What goes wrong
- **Correct usage:** How to query it properly
- **Example:** Working CQL snippet -->

## Query Patterns

<!-- Add reusable investigation query patterns:

### Pattern Name
- **Use case:** When to use this pattern
- **Query:**
  ```
  CQL query here
  ```
-->
