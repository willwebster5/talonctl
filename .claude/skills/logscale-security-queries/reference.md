# CQL Syntax Reference

Quick reference for CrowdStrike Query Language syntax and common operations.

## Basic Query Structure

```cql
// Event filtering
#event_simpleName=<EventType>
| <field>=<value>
| <field>!<value>

// Regex matching
| <field>=/pattern/

// Field existence
| <field>=*

// Numeric comparisons (in filters, not case statements)
| <field> > <value>
| <field> < <value>
```

## Field Operations

### Assignment
```cql
// Create new field
| _NewField := "value"
| _NewField := <ExistingField>

// Format string
| _Message := format("Text %s", field=[<FieldName>])
```

### Renaming
```cql
| rename(<old_field>, as=<new_field>)
```

### Field Selection
```cql
// Keep only specified fields
| select([<field1>, <field2>])

// Remove specified fields
| drop([<field1>, <field2>])
```

## Aggregation Functions

```cql
| groupBy([<field1>, <field2>], function=[
    count(),                    // Count events
    dc(<field>),               // Distinct count
    sum(<field>),              // Sum values
    min(<field>),              // Minimum value
    max(<field>),              // Maximum value
    avg(<field>),              // Average value
    collect(<field>)           // Collect values into array
])
```

### Naming Aggregation Results

```cql
// ✅ CORRECT - Use as= for count, sum, min, max, avg
| groupBy([UserId], function=[
    count(as=TotalEvents),
    sum(BytesSent, as=TotalBytes),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)
])

// ❌ WRONG - := assignment NOT allowed in groupBy function list
| groupBy([UserId], function=[
    MyCount := count()  // ❌ Syntax error
])

// ❌ WRONG - collect() does NOT support as= or :=
| groupBy([UserId], function=[
    collect(event.action, as=Actions)  // ❌ as= not supported
])

// ✅ CORRECT - collect() uses original field name
| groupBy([UserId], function=[
    collect([event.action, source.ip])  // Result: event.action array
])
| ActionList := format("%s", field=[event.action])  // Reference by original name
```

## Joins and Lookups

### Join with Subquery
```cql
| join({
    <subquery>
}, field=<join_field>, include=[<field1>, <field2>])
```

### CSV Lookup / match()

```cql
// Basic lookup - match field against CSV column
| match(file="<filename>.csv", field=<field>, include=[<col1>, <col2>], ignoreCase=true)

// Match with strict=false (keep events with no match, fields will be null)
| match(file="kms_key_generation", field=[_identity, user.name], strict=false)

// Match on multiple fields (composite key join)
| match(file="baseline_stats", field=[baseline.entity_id, baseline.event_type], strict=false)

// Match with column mapping (CSV column name differs from event field)
| match(file="falcon/investigate/chassis.csv", column=ChassisType_decimal,
    field=ChassisType_decimal, include=ChassisType, strict=false)

// Negative match - exclude known values via CSV
| NOT match(file="known_good_domains.csv", column=domain,
    field=dns_query_registered_domain, include=[])
```

**Source**: `resources/detections/crowdstrike/crowdstrike___endpoint___suspicious_hostname_or_ip_location.yaml`, `resources/detections/crowdstrike/crowdstrike_endpoint_potential_dns_tunneling_via_randomized_subdomains.yaml`

**Key Parameters**:
| Parameter | Description |
|-----------|-------------|
| `file` | CSV filename or defineTable name |
| `field` | Event field(s) to match against |
| `column` | CSV column to match (if different from field name) |
| `include` | CSV columns to bring into the event |
| `strict` | `true` (default) = drop non-matching events; `false` = keep all |
| `ignoreCase` | Case-insensitive matching |

### defineTable() - Historical Baselines

```cql
// Create a baseline table from historical data
defineTable(
    query={
        #Vendor="aws" #event.module="cloudtrail"
        | groupBy([user.name, Vendor.requestParameters.keyId],
            function=[count(as="_baseline_count")])
        | case {
            _baseline_count > 10 | _frequent_generator := true;
            * | _frequent_generator := false
        }
    },
    include=[user.name, Vendor.requestParameters.keyId, _frequent_generator],
    name="baseline_stats",     // Table name for match()
    start=30d,                 // Lookback window start
    end=70m                    // Exclude recent data
)

// Main query - match current events against the baseline
| #Vendor="aws" #event.module="cloudtrail"
| match(file="baseline_stats", field=user.name, strict=false)
| case {
    _frequent_generator=false;   // In baseline but infrequent
    _frequent_generator!=*;      // Not in baseline at all (new behavior)
}
```

**Source**: `resources/detections/aws/aws_cloudtrail_kms_anomalous_data_key_generation.yaml`

**Key Parameters**:
| Parameter | Description |
|-----------|-------------|
| `query` | CQL query to compute the baseline |
| `include` | Fields to make available via match() |
| `name` | Reference name used in `match(file=...)` |
| `start` | How far back to look (e.g., `7d`, `30d`) |
| `end` | Exclude recent data to avoid self-detection (e.g., `1h`, `70m`) |

**Common Patterns**:
- `start=7d, end=1h` -- 7-day baseline, exclude last hour
- `start=30d, end=70m` -- 30-day baseline, exclude last 70min (matches 1h schedule + grace)
- Handle missing baselines: `case { threshold!=* | threshold := 0; *; }` or `default(field=threshold, value=0)`

### correlate() - Multi-Event Correlation

For behavioral rules that detect patterns across multiple events. See [correlate-function.md](correlate-function.md) for complete reference.

```cql
correlate(
  QueryName1: { filter1 },
  QueryName2: {
    filter2
    | fieldA <=> QueryName1.fieldB   // Link operator
  },
  sequence=true,                      // Enforce event order
  within=1h,                          // Time window
  globalConstraints=[shared_field]    // Fields all events must share
)
```

**Key Parameters:**
| Parameter | Description |
|-----------|-------------|
| `sequence` | `true` = events must occur in order |
| `within` | Time window (e.g., `15m`, `1h`, `24h`) |
| `globalConstraints` | Fields all queries must share |
| `jitterTolerance` | Allow timing tolerance for near-simultaneous events |

**Link Operator `<=>`:**
```cql
| user.email <=> OtherQuery.user.email  // Link fields between queries
```

**Output fields are prefixed:** `QueryName1.field`, `QueryName2.field`

## Enrichment Functions

### IP Geolocation & Network
```cql
| ipLocation(<ip_field>)
// Adds: <field>.country, <field>.city, <field>.latitude, <field>.longitude

| asn(<ip_field>)
// Adds: <field>.org (ASN organization name)

// CIDR subnet check
| cidr(aip, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
| NOT cidr(aip, subnet=["10.0.0.0/8"])  // Exclude private IPs
```

### Timestamp & Duration
```cql
// Format timestamp for display
| _TimestampEST := formatTime("%Y-%m-%d %H:%M:%S", field=@timestamp, timezone="America/New_York")

// Time bucketing for aggregation
| time_bucket := formatTime("%Y-%m-%d %H", field=@timestamp)

// Current time reference
| _current_time := now()

// Duration formatting (epoch ms to human-readable)
| formatDuration(AttackDuration, from=ms, precision=2, as=DurationFormatted)

// Math on timestamps (epoch milliseconds)
| AttackDurationMinutes := (LastAttempt - FirstAttempt) / 60000
```

### String Formatting
```cql
// Basic format with field interpolation
| _Output := format("Text: %s, Number: %d", field=[<string_field>, <number_field>])

// Multi-line format strings
| session_details := format("[%s] %s connected from %s %s\n  Source: %s\n  Agent: %s",
    field=[_time, user.name, source.ip, source.ip.country, source.ip.org, user_agent.original])

// Numeric formatting
| AttackVelocity := format("%0.2f", field=AttackVelocity)
| MinutesSince := format("%0.1f", field=MinutesSinceLastAttempt)
```

**Source**: `resources/detections/aws/aws___cloudtrail___potential_session_hijacking.yaml`, `resources/detections/microsoft/microsoft_entra_id_multiple_failed_login_optimized.yaml`

### Statistical Functions
```cql
// In groupBy() aggregation
| groupBy([baseline.entity_id], function=[
    avg(event_count, as=baseline.avg),
    stdDev(event_count, as=baseline.std_dev),
    count(as=TotalEvents),
    sum(BytesSent, as=TotalBytes),
    count(field, distinct=true, as=UniqueCount),
    selectLast([user.id, user.full_name])    // Last value seen
  ])

// Math operations
| threshold := baseline.avg + 3 * baseline.std_dev   // 3-sigma threshold
| _totalGigaBytes := _totalBytes / 1000000000
| Failures_15m := math:floor(Failures_15m)         // Round down
```

**Source**: `resources/detections/generic/anomolous_usb_exfiltration.yaml`, `resources/detections/microsoft/microsoft_entra_id_multiple_failed_login_optimized.yaml`

### Null Handling & Defaults
```cql
// Set default for missing fields
| default(field=threshold, value=0)
| default(field=bytes_threshold, value=104857600)

// Check field existence in case statement
| case {
    threshold!=* | threshold := 0;    // Field doesn't exist
    *;
}

// Coalesce - use first non-null value
| coalesce([Vendor.id, Vendor.properties.id], as="_event_id")
| _identity := coalesce([Vendor.userIdentity.arn, user.id])
```

### JSON Operations
```cql
// Parse JSON string into structured fields
| parseJson(Vendor.targetResources[0].modifiedProperties[0].oldValue, prefix=oldParsed)

// Write array/object to JSON string
| writeJson("newResults[*]", as=newJson)
```

## Sorting and Limiting

```cql
// Sort
| sort(<field>, order=asc)
| sort(<field>, order=desc)

// Limit results
| head(10)   // First 10
| tail(100)  // Last 100
```

## Output Formatting

```cql
// Table output
| table([<field1>, <field2>, <field3>])

// Select specific fields
| select([<field1>, <field2>])
```

## Common Functions

### String Operations
```cql
| lower(<field>)          // Convert to lowercase
| upper(<field>)          // Convert to uppercase
| length(<field>)         // String length
| replace(<pattern>, <replacement>, field=<field>)
```

### Regex Operations

```cql
// Basic regex match (filter)
| field=/pattern/
| field=/pattern/i                     // Case-insensitive

// Negative regex match
| field!=/pattern/i

// Named capture groups - extract values into new fields
| user.email=/\@(?<sourceDomain>[^$]+)/i
| forwardingObserved[0] = /\s\=\s(?<destinationAddress>.*)/i
| file.name=/(?<file.confidentiality>CONFIDENTIAL|RESTRICTED|PROPRIETARY|SECRET)/i

// Regex extraction function (alternative to capture groups)
| regex("<pattern>", field=<field>, strict=false)

// Regex in in() operator
| event.action=/^(?:Delete|Put|Create|Update|Attach|Detach)/

// String splitting with regex-like delimiters
| splitString(field=DomainName, by="\\.", index=-1)    // Last element
| splitString(field=DomainName, by="\\.", index=-2)    // Second to last

// Shannon entropy (string randomness analysis)
| shannonEntropy(DomainName)
```

**Source**: `resources/detections/microsoft/microsoft_entra_id_suspicious_inbox_forwarding.yaml`, `resources/detections/crowdstrike/crowdstrike_endpoint_potential_dns_tunneling_via_randomized_subdomains.yaml`

**Key Patterns**:
- Named captures: `(?<fieldName>pattern)` - assigns matched text to a field
- Non-capturing groups: `(?:alt1|alt2)` - grouping without creating a field
- Case-insensitive: append `/i` flag
- Negative index in `splitString`: `-1` = last element, `-2` = second-to-last
- `shannonEntropy()` returns a float measuring string randomness (>4 = suspicious for DNS)

### Array Operations

```cql
// Array length
| length(<array_field>)

// Check if array contains a value
| array:contains(array="event.category[]", value="authentication")

// Evaluate each element in an object array, producing a new array
| objectArray:eval("Vendor.Parameters[]", asArray="params[]", var=x, function={
    params := format("%s = %s", field=[x.Name, x.Value])
  })

// Filter array elements by condition
| array:filter(array="params[]", var=y, asArray="filtered[]", function={
    y = /ForwardTo|RedirectTo/i
  })

// Evaluate array elements with complex logic (case statements inside)
| objectArray:eval(array="oldParsed[]", asArray="oldResults[]", var="o", function={
    case {
        o.DeviceTag=/android/i | oldResults := "Android Device Found";
        o.DeviceTag=/ios/i | oldResults := "IOS MFA Device Found";
    }
  })

// Convert array to JSON string for regex searching
| writeJson("newResults[*]", as=newJson)
| newJson=/android/i newJson=/ios/i    // Check array contents via regex

// Array element access (0-indexed)
| forwardingObserved[0] = /\s\=\s(?<destinationAddress>.*)/i

// Create arrays from strings
| destinationAddressArray := splitString(destinationAddress, by=";")

// Evaluate array with format()
| array:eval("destinationAddressArray[]", var=addr, asArray="results[]", function={
    format("%s %s", field=["sourceDomain", "addr"], as=results)
  })
```

**Source**: `resources/detections/microsoft/microsoft_entra_id_suspicious_inbox_forwarding.yaml` and `microsoft_entra_id_new_mfa_device_operating_system_observed.yaml`

**Key Rules**:
- Array field references use `[]` suffix: `"event.category[]"`, `"params[]"`
- `objectArray:eval` iterates object arrays and produces new arrays
- `array:filter` selects elements matching a condition
- `array:contains` checks for exact value membership
- `writeJson()` converts arrays to JSON strings for regex operations
- Variable names in `var=` are scoped to the function block

### if() Function

```cql
// Syntax: if(condition, then=value, else=value)
// Use for conditional field assignment OUTSIDE case statements

// Conditional validation - skip check when field doesn't exist
| testLogin := if(successLogon, then=(loggedUser==lowPrivUser), else=true)
| test(testLogin)

// Conditional chronology check
| testCron1 := if(successLogon, then=(minLogonTime<minLowPrivTime), else=true)
| test(testCron1)
```

**Source**: `resources/detections/crowdstrike/crowdstrike___endpoint___potential_privilege_escalation_via_exploit.yaml` (lines 185-194)

**When to Use if() vs case**:
- Use `if()` when you need a boolean result based on a field's existence
- Use `if()` for inline conditional assignments that return a value
- Use `case {}` for multi-branch decision trees (3+ conditions)
- `if()` returns a value; `case {}` assigns fields within branches

### Custom Functions (Saved Searches)

```cql
// Call saved search functions with $function_name() syntax
| $aws_service_account_detector(strict_mode="true", include_temp="false")
// Creates: aws.service_account_type, aws.is_service_account, aws.svc_detection_confidence

// Pass named parameters as key="value" pairs
| $trusted_network_detector(extend_trust="true", include_private="true")
// Creates: net.is_sase, net.is_excluded, net.provider, net.exclusion_reason

// Chain multiple functions
| $entraid_enrich_user_identity()
| $entraid_check_privileged_groups(strict_mode="false")
```

**Source**: `resources/saved_searches/trusted_network_detector.yaml`, `resources/detections/aws/aws_cloudtrail_kms_anomalous_data_key_generation.yaml`

## Platform-Specific Notes

### Reserved Fields
- `@timestamp` - Event timestamp (epoch milliseconds)
- `@rawstring` - Raw event data
- `#event_simpleName` - Event type identifier
- `aid` - Agent ID (CrowdStrike)

### NG-SIEM Behavioral Detection Fields

Fields for Rule Trigger Events (RTE) from behavioral rules:

| Field | Values | Description |
|-------|--------|-------------|
| `Ngsiem.event.type` | `ngsiem-rule-trigger-event` | Identifies rule trigger event |
| `Ngsiem.event.outcome` | `correlation-rule-detection`, `behavioral-detection`, `behavioral-case` | Detection type |
| `Ngsiem.part.query.{name}` | Event IDs | Links to underlying events for each named query |
| `Ngsiem.event.subtype` | `result_event`, `result_underlying_event` | Event classification in RME |
| `Ngsiem.part.query.name` | Query name | Which correlate() query matched |

**Querying RTEs:**
```cql
#repo="xdr_indicatorsrepo"
Ngsiem.event.type="ngsiem-rule-trigger-event"
Ngsiem.event.outcome="behavioral-detection"
```

### Naming Conventions
- Temporary fields: Start with underscore `_FieldName`
- User fields: No prefix restriction
- System fields: Start with `@` or `#`

### Event Correlation Functions

```cql
// selfJoinFilter - correlate multiple event types sharing a field
| selfJoinFilter(field=[aid],
    where=[
        { initialAccess="true" OR successLogon="true" },
        { lowPrivExec="true" },
        { highPrivExec="true" }
    ], prefilter=true
)

// session() - group related events with time gaps (inside groupBy)
| groupBy([aid], function=[
    session(
        [
            collect([field1, field2]),
            min(timestamp1, as="minTime1"),
            min(timestamp2, as="minTime2")
        ],
        maxpause=15m     // Max gap between events in a session
    )
  ])
```

**Source**: `resources/detections/crowdstrike/crowdstrike___endpoint___potential_privilege_escalation_via_exploit.yaml` (lines 156-180)

**Key Points**:
- `selfJoinFilter` requires events to share field values (like `aid`)
- Each `where` clause defines an event type; all must be present
- `session()` groups events with `maxpause` max gap between them
- `_duration` field is automatically added by session()

### Performance Tips
1. Filter early - Use specific filters before aggregations
2. Limit results - Use head() or tail() to reduce data processing
3. Avoid wildcards - Be specific with field filters when possible
4. Order case statements - Put most common conditions first
5. Use efficient aggregations - dc() is faster than collect() + length()
6. Pre-calculate arithmetic - Do division/multiplication before case statements, not inside test()
7. Use `limit=max` in groupBy() when you need all results (default is 200)

## Integration Points

### CrowdStrike EDR
```cql
// Agent ID based filtering
| aid=<agent_id>

// Event type filtering
| #event_simpleName=ProcessRollup2
| #event_simpleName=NetworkConnectIP4
| #event_simpleName=FileWritten
```

### AWS CloudTrail
```cql
// User identity
| userIdentity.principalId=<user>

// Event types
| eventName=<aws_action>
```

### Microsoft Entra ID
```cql
// User principal
| UserPrincipalName=<user>@<domain>

// Application
| AppDisplayName=<app_name>
```

## Example Query Template

```cql
// Step 1: Filter events
#event_simpleName=<EventType>
| <initial_filters>

// Step 2: Exclude known-good
| <service_account_detection or manual exclusions>

// Step 3: Aggregate (if needed)
| groupBy([<key_fields>], function=[count()])

// Step 4: Risk categorization
| case {
    <critical_condition> | _Risk := "Critical" | _Score := 90 ;
    <high_condition> | _Risk := "High" | _Score := 70 ;
    * | _Risk := "Low" | _Score := 10 ;
}

// Step 5: Enrichment
| match(file="<lookup>.csv", field=<field>, include=[<cols>])
| ipLocation(<ip_field>)
| _Timestamp := formatTime("%Y-%m-%d %H:%M:%S", field=@timestamp, timezone="America/New_York")

// Step 6: Output
| table([_Score, _Risk, <key_fields>, _Timestamp])
| sort(_Score, order=desc)
```

---

## Query Optimization Order

Apply pipeline stages in this order for maximum performance. Earlier stages reduce event volume before expensive operations run.

```
1. Time filter      — implicit (@timestamp range from UI)
2. Tag filters      — #repo, #event_simpleName, #Vendor (indexed; fastest)
3. Field filters    — event.action="X", severity="high" (equality/prefix)
4. Negative filters — field != "value" (apply after positives)
5. Regex            — field = /pattern/ (expensive — minimize or defer)
6. Functions        — $saved_search(), ipLocation(), asn() (network I/O)
7. Aggregate        — groupBy(), stats(), count() (reduces cardinality)
8. Rename/assign    — field := value, format() (low cost, after aggregation)
9. Join             — match(), defineTable() (expensive — after aggregation)
10. View            — table(), select(), sort() (final output shaping)
```

**Why it matters:** Moving expensive operations earlier multiplies their cost. Example: `ipLocation()` before `groupBy()` runs once per raw event; after `groupBy()` it runs once per unique IP. On a 100k-event query with 200 unique IPs, that's 100k vs 200 enrichment calls — ~2s vs 1.8s difference in practice, much larger at scale.

**Rule of thumb:** Filter → Aggregate → Enrich → Join → Display.

---

## `table()` vs `select()`

These look similar but behave very differently.

| | `table()` | `select()` |
|---|---|---|
| Type | Aggregation function | Field pluck (projection) |
| Row limit | 200 rows (hard limit) | No row limit |
| Effect on pipeline | Terminates aggregation | Passes events through |
| Use case | Final display output | Remove unwanted fields mid-query |

```cql
// ✅ table() — final display, max 200 rows
| table([field1, field2, field3])

// ✅ select() — pass-through projection, unlimited
| select([field1, field2, field3])
```

Use `table()` only as the final step when displaying results in the UI. Use `select()` when you need to drop fields mid-pipeline without capping rows.

---

## `$falcon/helper:enrich()` — Built-in Field Reference

CrowdStrike's built-in enricher adds human-readable labels to numeric/coded fields. Supports 90+ fields.

```cql
| $falcon/helper:enrich(field=LogonType)
| $falcon/helper:enrich(field=SubStatus)
| $falcon/helper:enrich(field=IntegrityLevel)
```

**Commonly used fields:**

| Field | Example Raw Value | Enriched Output |
|-------|-------------------|-----------------|
| `LogonType` | `3` | `Network` |
| `SubStatus` | `0xc000006a` | `Wrong password` |
| `IntegrityLevel` | `12288` | `High` |
| `ProductType` | `3` | `Server` |
| `TlsVersion` | `771` | `TLS 1.2` |
| `AuthenticationPackage` | — | NTLM / Kerberos / Negotiate |
| `BootType` | — | Normal boot / Fast startup / Hibernate |
| `EncryptionType` | — | AES / RC4 / DES |
| `ImpersonationLevel` | — | Impersonation / Identification |
| `KeyLength` | — | 128 / 256 |
| `LoginFlags` | — | Bitmask decoded to flag names |
| `NetworkAccessType` | — | Wired / Wireless |
| `ProcessCreationFlags` | — | Bitmask decoded |
| `ProtectionType` | — | PPL level |
| `Status` | — | NTSTATUS human label |
| `UserAccountControl` | — | Bitmask decoded |

**IntegrityLevel numeric values:**
| Value | Label |
|-------|-------|
| `0` | Untrusted |
| `4096` | Low |
| `8192` | Medium |
| `8448` | Medium Plus |
| `12288` | High |
| `16384` | System |
| `20480` | Protected Process |

**Detect high-integrity execution (suspicious if user-launched):**
```cql
#event_simpleName=ProcessRollup2
| IntegrityLevel >= 12288
| $falcon/helper:enrich(field=IntegrityLevel)
```

---

## `ioc:lookup()` — Falcon Intelligence IOC Lookup

Query CrowdStrike Falcon Intelligence IOC database inline within a CQL query.

```cql
// Check a domain against Falcon Intelligence
| ioc:lookup(field=DomainName, type="domain")

// Check an IP
| ioc:lookup(field=aip, type="ip_address")

// Check a file hash
| ioc:lookup(field=SHA256HashData, type="sha256")
```

**Fields added by `ioc:lookup()`:**
- `ioc.malicious_confidence` — `high`, `medium`, `low`, `unverified`
- `ioc.type` — IOC type string
- `ioc.labels[]` — threat actor / malware family labels
- `ioc.published_date` — when the IOC was published

**Filter to confirmed malicious:**
```cql
| ioc:lookup(field=DomainName, type="domain")
| ioc.malicious_confidence=high
```

---

## `defineTable()` — In-Memory Join Types

`defineTable()` creates an in-memory lookup table from a subquery result for joining with the main event stream. Supports left, right, and inner join semantics.

```cql
// Inner join — only events with a match in the lookup table
| defineTable(query={
    <subquery producing key + enrichment fields>
  }, join=[key_field], type="inner")

// Left join — all events; unmatched get null enrichment fields (default)
| defineTable(query={
    <subquery>
  }, join=[key_field], type="left")

// Right join — only events matched in the right (lookup) side
| defineTable(query={
    <subquery>
  }, join=[key_field], type="right")
```

**When to use each:**
- **left** (default): Enrichment — keep all events, add optional context. Unmatched rows keep original fields.
- **inner**: Filter — only process events that appear in a reference set (e.g., only known-bad IPs).
- **right**: Rare — use when the lookup side should drive the output, not the event stream.

**Example — enrich events with account type from a lookup subquery:**
```cql
#repo=cloudtrail
| defineTable(query={
    #repo=cloudtrail userIdentity.type=AssumedRole
    | groupBy([userIdentity.userName], function=[count()])
  }, join=[userIdentity.userName], type="left")
```
