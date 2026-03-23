# correlate() Function Reference

The `correlate()` function identifies patterns across multiple events by linking them through specified correlation keys. It enables behavioral detection rules that find "constellations" of related events within time windows.

## When to Use correlate()

Use `correlate()` when you need to:
- Detect **attack chains** (recon → escalation → persistence)
- Find **authentication patterns** (failed logins followed by success)
- Correlate **3+ event types** (join only supports 2)
- Enforce **event sequencing** (A must happen before B)
- Create **behavioral detections** vs single-event rules

## Complete Syntax

```cql
correlate(
  NAME1: { QUERY1 [| LINK]* } [QUERYATTR],
  NAME2: { QUERY2 [| LINK]* } [QUERYATTR],
  ...
  OPTIONS
)
```

## Parameters Reference

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `query` | query | Yes | — | Named queries: `NAME: { QUERY }` |
| `sequence` | boolean | No | `false` | Enforce chronological event order |
| `within` | relative-time | No | — | Max time span between events (e.g., `15m`, `1h`, `24h`) |
| `sequenceBy` | array | No | `[@timestamp, @timestamp.nanos]` | Fields for ordering when `sequence=true` |
| `jitterTolerance` | relative-time | No | — | Allow timing tolerance for near-simultaneous events |
| `globalConstraints` | array | No | — | Fields ALL events must share (simplifies links) |
| `maxPerRoot` | integer | No | `1` | Max matches per root query event |
| `root` | string | No | First query | Root node for constellation matching |
| `includeConstraintValues` | boolean | No | `true` | Include linked constraint fields in output |
| `includeMatchesOnceOnly` | boolean | No | `false` | Each event matches only once per constellation |
| `iterationLimit` | integer | No | `5` | Max iterations (range: 1–10) |

### Query Attributes

Each query can have optional attributes:

```cql
correlate(
  EventA: { filter1 } include: [field1, field2],  // Include extra fields
  EventB: { filter2 | link },
  ...
)
```

| Attribute | Description |
|-----------|-------------|
| `include: [fields]` | Additional fields to include in output (beyond linked fields) |

## Link Operator: `<=>`

The `<=>` operator establishes correlations between queries. Fields need not have identical names.

### Basic Syntax

```cql
| fieldA <=> OtherQuery.fieldB
```

### Link Rules

1. **Order matters within queries**: Links appear after filters with `|`
2. **Reference other queries by name**: `Query1.field`
3. **Exact value match required**: Fields must have identical values
4. **Multiple links allowed**: Chain with additional `|` operators

### Example

```cql
correlate(
  LoginFail1: {
    event.outcome="failure"
  },
  LoginFail2: {
    event.outcome="failure"
    | user.email <=> LoginFail1.user.email      // Same user
    | source.ip <=> LoginFail1.source.ip        // Same IP
  },
  LoginSuccess: {
    event.outcome="success"
    | user.email <=> LoginFail1.user.email      // Same user
  },
  sequence=true,
  within=30m
)
```

## Heterogeneous Correlation Keys

By default, you might assume every query in a `correlate()` must share the same key. That's
not required. Each `<=>` link is scoped to a specific **pair** of queries — allowing different
pairs to pivot on completely different fields.

This is what enables cross-source correlations where vendors don't share a common identifier:

```
zscaler ──(email)──► okta
zscaler ──(IP)──────► falcon
```

```cql
correlate(
  // Anchor: Zscaler/SASE establishes BOTH email and external IP context
  zscaler: {
    #Vendor=zscaler
  } include: [user.email, client.ip],

  // Okta: linked to zscaler by email (user.name on one side, user.email on the other)
  okta: {
    #Vendor=okta
    | user.name <=> zscaler.user.email     // email is the join key for this pair
  } include: [user.email, client.ip],

  // Falcon: linked to zscaler by external IP (completely different field name on each side)
  falcon: {
    #Vendor=crowdstrike
    | aip <=> zscaler.client.ip            // IP is the join key for this pair
  } include: [ComputerName, aip],

  sequence=false, within=60m
)
```

**Key observations**:
- `okta` and `falcon` are NOT directly linked to each other — they're both anchored to `zscaler`
- The `<=>` operator matches by **value**, not by field name — `user.name` can equal `user.email` if they hold the same value
- `globalConstraints` can't replace heterogeneous keys; use per-query `<=>` links when pairs differ
- The first query (`zscaler`) is typically the "anchor" — the source that carries context needed by all other queries

**When to use**: Any time you're correlating across vendors that don't share a common
identifier (email vs. IP vs. hostname vs. UUID).

---

## Using globalConstraints

For fields that ALL queries must share, use `globalConstraints` instead of repeating links:

### Without globalConstraints (verbose)

```cql
correlate(
  EventA: { filter1 },
  EventB: { filter2 | user.id <=> EventA.user.id },
  EventC: { filter3 | user.id <=> EventA.user.id },
  EventD: { filter4 | user.id <=> EventA.user.id },
  within=1h
)
```

### With globalConstraints (cleaner)

```cql
correlate(
  EventA: { filter1 },
  EventB: { filter2 },
  EventC: { filter3 },
  EventD: { filter4 },
  within=1h,
  globalConstraints=[user.id]  // All events must have same user.id
)
```

## Output Fields

Results include prefixed field names from each query:

| Field Pattern | Description |
|---------------|-------------|
| `QueryName.fieldname` | Field from specific query (e.g., `LoginSuccess.user.email`) |
| `@id` | Result event ID |
| `@timestamp` | Result timestamp |
| `@ingesttimestamp` | Ingestion timestamp |

### Accessing Output

```cql
correlate(
  FailedLogin: { event.outcome="failure" },
  SuccessLogin: { event.outcome="success" | user.email <=> FailedLogin.user.email },
  sequence=true,
  within=15m
)
// Output fields:
// - FailedLogin.user.email
// - FailedLogin.source.ip
// - SuccessLogin.user.email
// - SuccessLogin.source.ip

| table([SuccessLogin.user.email, FailedLogin.source.ip])
```

## Sequence vs Non-Sequence

### sequence=true

Events MUST occur in the order defined:

```cql
correlate(
  Step1: { event.action="CreateUser" },
  Step2: { event.action="AttachPolicy" | ... },
  Step3: { event.action="CreateAccessKey" | ... },
  sequence=true,   // Step1 → Step2 → Step3 (in order)
  within=1h
)
```

### sequence=false (default)

Events can occur in any order within the time window:

```cql
correlate(
  AlertA: { rule.name=/BruteForce/ },
  AlertB: { rule.name=/DataExfil/ | user.name <=> AlertA.user.name },
  within=4h,
  sequence=false   // Either alert can come first
)
```

### Using jitterTolerance

When events are "nearly simultaneous" but logged with slight timestamp differences:

```cql
correlate(
  EventA: { ... },
  EventB: { ... | field <=> EventA.field },
  sequence=true,
  within=1h,
  jitterTolerance=5s   // Allow 5 second tolerance between "ordered" events
)
```

**Note**: `jitterTolerance` must not exceed `within` value.

## NG-SIEM Behavioral Detection Fields

When a behavioral rule triggers, these fields identify the detection:

### Rule Trigger Events (RTE)

| Field | Values | Description |
|-------|--------|-------------|
| `Ngsiem.event.type` | `ngsiem-rule-trigger-event` | Identifies RTE |
| `Ngsiem.event.outcome` | `correlation-rule-detection`, `behavioral-detection`, `behavioral-case` | Detection type |
| `Ngsiem.part.query.{name}` | Event IDs | Links to underlying events for each query |

### Rule Match Events (RME)

| Field | Values | Description |
|-------|--------|-------------|
| `Ngsiem.event.subtype` | `result_event`, `result_underlying_event` | Event classification |
| `Ngsiem.part.query.name` | Query name | Which query matched this event |

## Common Patterns

### Pattern 1: Failed Logins → Success

```cql
correlate(
  FailedAttempts: {
    #event.module="entra_id"
    event.outcome="failure"
    event.action=/UserLogon|Sign-in/
  },
  SuccessfulLogin: {
    #event.module="entra_id"
    event.outcome="success"
    event.action=/UserLogon|Sign-in/
    | user.email <=> FailedAttempts.user.email
  } include: [source.ip, user_agent.original],
  sequence=true,
  within=30m,
  globalConstraints=[user.email]
)
```

### Pattern 2: Multi-Stage AWS Attack

```cql
correlate(
  Recon: {
    #Vendor="aws"
    event.action=~in(values=["DescribeInstances", "ListBuckets", "GetAccountAuthorizationDetails"])
  },
  PrivEsc: {
    #Vendor="aws"
    event.action=~in(values=["CreateUser", "AttachUserPolicy", "PutRolePolicy"])
    | Vendor.userIdentity.arn <=> Recon.Vendor.userIdentity.arn
  },
  Persist: {
    #Vendor="aws"
    event.action=~in(values=["CreateAccessKey", "CreateLoginProfile", "UpdateLoginProfile"])
    | Vendor.userIdentity.arn <=> Recon.Vendor.userIdentity.arn
  },
  sequence=true,
  within=2h,
  globalConstraints=[Vendor.userIdentity.arn]
)
```

### Pattern 3: Cross-Detection Correlation

Chain multiple rule triggers into compound detection:

```cql
correlate(
  BruteForceAlert: {
    #repo="xdr_indicatorsrepo"
    Ngsiem.event.type="ngsiem-rule-trigger-event"
    Ngsiem.event.outcome="correlation-rule-detection"
    rule.name=/Brute Force|Password Spray/i
  },
  LateralMovement: {
    #repo="xdr_indicatorsrepo"
    Ngsiem.event.type="ngsiem-rule-trigger-event"
    Ngsiem.event.outcome="correlation-rule-detection"
    rule.name=/Lateral Movement|RDP/i
    | user.name <=> BruteForceAlert.user.name
  },
  within=24h,
  globalConstraints=[user.name]
)
```

### Pattern 4: CrowdStrike EDR + Cloud Events

```cql
correlate(
  ProcessExec: {
    #event_simpleName="ProcessRollup2"
    ImageFileName=/powershell|cmd/i
  },
  CloudAPICall: {
    #Vendor="aws"
    event.action=/Put|Create|Delete/
    | user.name <=> ProcessExec.UserName
  },
  within=30m
)
```

## Referencing Detection Types

### CrowdStrike First-Party Detections (DSE)

```cql
correlate(
  EDRDetection: {
    #event_simpleName="EPPDetectionSummaryEvent"
    Tactic=/Persistence|PrivilegeEscalation/
  },
  ...
)
```

Supported DSE types:
- `EPPDetectionSummaryEvent` - Endpoint detection
- `IDPDetectionSummaryEvent` - Identity detection
- `XDRDetectionSummaryEvent` - XDR detection
- `CloudDetectionSummaryEvent` - Cloud detection
- `LogScaleDetectionSummaryEvent` - LogScale detection
- `CustomIOADetectionSummaryEvent` - Custom IOA

### Third-Party CIM Alerts

```cql
correlate(
  ThirdPartyAlert: {
    #event.kind="alert"
    Vendor.name="Palo Alto"
  },
  ...
)
```

### Correlation Rule Detections (RTEs)

```cql
correlate(
  PriorRuleHit: {
    #repo="xdr_indicatorsrepo"
    Ngsiem.event.type="ngsiem-rule-trigger-event"
    Ngsiem.event.outcome="correlation-rule-detection"
    rule.name="My Other Rule Name"
  },
  ...
)
```

## Limitations and Constraints

### Cannot Use

- ❌ After aggregators (`groupBy`, `count`, etc.)
- ❌ Inside function parameters
- ❌ Aggregate functions within queries
- ❌ Comparison operators other than `<=>`
- ❌ After source functions (`createEvents()`, `readFile()`)

### Must Consider

- Results must fit within memory quota
- `jitterTolerance` cannot exceed `within`
- Complex correlations may require multiple iterations

### Best Practices

1. **Filter early**: Put specific filters first in each query
2. **Use globalConstraints**: Simplifies queries, improves performance
3. **Smallest practical `within`**: Narrow time windows reduce search scope
4. **Use `sequence=true` only when needed**: Non-sequence is more flexible
5. **Include specific fields**: Use `include: [field1]` instead of `include: *`
6. **Test incrementally**: Start with 2 queries, add more after validation

## Troubleshooting

### "Unknown error" after correlate()

Likely cause: Using correlate() after an aggregator or inside a function.

```cql
// ❌ WRONG - correlate after groupBy
| groupBy([user], function=[count()])
| correlate(...)

// ✅ CORRECT - correlate first, then aggregate results
correlate(...)
| groupBy([SuccessLogin.user.email], function=[count()])
```

### No results returned

1. Check time window (`within`) is appropriate for your data
2. Verify link fields exist in all queries
3. Ensure field values actually match (case-sensitive)
4. Try without `sequence=true` first

### Memory quota exceeded

1. Add more specific filters to reduce event volume
2. Use narrower time windows
3. Add `globalConstraints` to narrow correlation keys
4. Consider splitting into multiple rules

## Complete Example

```cql
// Detect brute force followed by successful login and privilege escalation
correlate(
  BruteForce: {
    #event.module="entra_id"
    event.outcome="failure"
    event.action=/UserLogon|Sign-in/
  },
  SuccessLogin: {
    #event.module="entra_id"
    event.outcome="success"
    event.action=/UserLogon|Sign-in/
    | user.email <=> BruteForce.user.email
  } include: [source.ip, source.geo.country_name],
  PrivilegeGrant: {
    #event.module="entra_id"
    event.action=/Add member to role|Add eligible member/
    | user.email <=> BruteForce.user.email
  } include: [azure.auditlogs.properties.target_resources],
  sequence=true,
  within=4h,
  globalConstraints=[user.email]
)
| case {
    SuccessLogin.source.geo.country_name!="United States" | _Risk := "Critical" ;
    * | _Risk := "High" ;
}
| table([
    _Risk,
    SuccessLogin.user.email,
    SuccessLogin.source.ip,
    SuccessLogin.source.geo.country_name,
    PrivilegeGrant.azure.auditlogs.properties.target_resources
])
```