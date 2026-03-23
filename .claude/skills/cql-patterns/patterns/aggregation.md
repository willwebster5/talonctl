# Aggregation Patterns

Patterns for counting, bucketing, and thresholding events. Reach for these when you need to
answer "how many", "how often", or "is this above normal" rather than "did this single event
happen."

## Pattern: groupBy with Threshold

**When to use:** Count events per entity and filter to anomalies exceeding a threshold
**Complexity:** Simple
**Log sources:** Any
**Requires:** None

### Template
```cql
#event_simpleName=YourEventType
// Replace with your filter criteria

// Assign per-event flags or categories (optional)
| case {
    FieldA=/pattern1/ | flag1:="1";
    FieldA=/pattern2/ | flag2:="1";
}

// Aggregate per entity
| groupBy([EntityKey1, EntityKey2], function=([
    sum(flag1, as=flag1Total),
    sum(flag2, as=flag2Total),
    selectLast([ContextField])
  ]), limit=max)

// Calculate composite score and apply threshold
| totalScore := flag1Total + flag2Total
| totalScore > 5  // Adjust threshold for your environment

// Format output
| table([EntityKey1, EntityKey2, totalScore, flag1Total, flag2Total, ContextField])
```

### Real Example
```cql
// Source: Query-Hub — count_windows_discovery_commands.yml
// Count discovery/recon commands per user and flag high-activity users

event_platform=Win #event_simpleName=ProcessRollup2
  FileName=/(whoami|ping|net1?|systeminfo|quser|ipconfig)/iF
| UserSid=S-1-5-21-*
| case {
    FileName=/whoami/iF     | whoami:="1";
    FileName=/ping/iF       | ping:="1";
    FileName=/net1?/iF      | net:="1";
    FileName=/systeminfo/iF | systeminfo:="1";
    FileName=/quser/iF      | quser:="1";
    FileName=/ipconfig/iF   | ipconfig:="1";
}
| groupBy([UserName, UserSid], function=([
    sum(whoami, as=whoami), sum(ping, as=ping), sum(net, as=net),
    sum(systeminfo, as=systeminfo), sum(quser, as=quser), sum(ipconfig, as=ipconfig),
    selectLast([CommandLine])
  ]), limit=max)
| rename(field="CommandLine", as="LastCommandRun")
| totalDiscovery := whoami + ping + net + systeminfo + quser + ipconfig
| totalDiscovery > 5
| table([UserName, UserSid, totalDiscovery, whoami, ping, net, systeminfo, quser, ipconfig, LastCommandRun])
```

### Pitfalls
- `groupBy` returns at most `limit` groups — use `limit=max` to avoid silently dropping results
- Threshold values are environment-specific; start high and tune down based on false positive rate
- `sum()` on string flags ("1") works because CQL coerces to integer; use string "1" not integer 1
- `selectLast()` returns only the most recent value — use `collect()` if you need all values

---

## Pattern: bucket() Time Windows

**When to use:** Group events into fixed time intervals and detect clusters of activity within a window
**Complexity:** Medium
**Log sources:** Any
**Requires:** None

### Template
```cql
#event_simpleName=YourEventType
// Replace with your filter criteria

// Bucket events into fixed time windows per entity
| bucket(span=10min,                              // Adjust window size
    field=[aid, ComputerName, ParentProcessId],    // Grouping dimensions
    function=[
        count(FileName, distinct=true, as=distinctCount),
        collect([FileName, CommandLine])
    ], limit=500)

// Apply threshold — fire when enough distinct items seen in one bucket
| test(distinctCount >= 3)  // Adjust threshold for your environment
```

### Real Example
```cql
// Source: Query-Hub — Frequency_Analysis_via_Program_Clustering.yml
// Detect recon tool clustering: 3+ distinct discovery tools in a 10-minute window

event_platform=Win #event_simpleName=ProcessRollup2
  FileName=/(whoami|arp|cmd|net|net1|ipconfig|route|netstat|nslookup|nltest|systeminfo|wmic|tasklist|tracert|ping|adfind|nbtstat|find|ldifde|netsh|wbadmin)\.exe/i
| bucket(span=10min,
    field=[cid, aid, ComputerName, ParentBaseFileName, ParentProcessId],
    function=[count(FileName, distinct=true, as=fNameCount), collect([FileName, CommandLine])],
    limit=500)
| test(fNameCount >= 3)
```

### Pitfalls
- `bucket()` creates fixed-edge windows aligned to clock time (e.g., :00, :10, :20) — activity spanning a boundary splits across two buckets
- Use `slidingTimeWindow()` instead if you need overlapping windows that don't miss boundary-spanning clusters
- `limit=500` caps the number of rows per bucket; increase or use `limit=max` for comprehensive results
- `span` should match your detection hypothesis — too wide = noise, too narrow = missed clusters

---

## Pattern: timeChart

**When to use:** Visualize event trends over time as a time series, optionally broken out by a category field
**Complexity:** Simple
**Log sources:** Any
**Requires:** None

### Template
```cql
#event_simpleName=YourEventType
// Replace with your filter criteria

// Simple count over time
| timeChart(span=30min, function=count(as=EventCount))

// Or: break out by a series field for multi-line charts
| timeChart(series=CategoryField)
```

### Real Example (Series Breakdown)
```cql
// Source: Query-Hub — mfa_status_monitoring.yml
// Monitor MFA approval/denial trends over time

#repo=base_sensor #event_simpleName=IdpPolicy*RuleMatch
| case {
    IdpPolicyMfaStatus=1   | IdpPolicyMfaStatus:="Approved";
    IdpPolicyMfaStatus=2   | IdpPolicyMfaStatus:="Denied";
    IdpPolicyMfaStatus=64  | IdpPolicyMfaStatus:="Resp. timeout";
    IdpPolicyMfaStatus=128 | IdpPolicyMfaStatus:="User not enrolled";
    IdpPolicyMfaStatus=256 | IdpPolicyMfaStatus:="Service Error";
}
| timeChart(series=IdpPolicyMfaStatus)
```

### Real Example (Simple Count)
```cql
// Source: Query-Hub — falcon_sensor_heartbeat_timechart.yml
// Plot sensor heartbeat frequency over time

#event_simpleName=SensorHeartbeat
| timeChart(span=30min, function=count(as=SensorHeartbeat))
```

### Pitfalls
- `timeChart` is an aggregation — you cannot add further filters or groupBy after it
- Default span is auto-calculated based on time range; specify `span=` for consistent bucket sizes
- `series` field with high cardinality (e.g., IP addresses) creates too many lines — pre-filter or use `groupBy` instead
- Rename numeric enum fields to labels BEFORE calling `timeChart(series=...)` for readable legends

---

## Pattern: session()

**When to use:** Group sequential events into sessions based on time gaps or field boundaries
**Complexity:** Medium
**Log sources:** Any
**Requires:** Events with timestamps and a grouping key

### Template
```cql
#event_simpleName=YourEventType
// Replace with your filter criteria

// Group events into sessions per entity
| groupBy([EntityKey1, EntityKey2],
    function=session([
        max(@timestamp),
        min(@timestamp)
    ]))

// Calculate session duration
| duration := _duration / 3600000  // Convert ms to hours
| age := formatDuration(_duration, precision=2)

// Format timestamps
| "First seen" := formatTime("%d-%b-%Y %H:%M:%S", field=_min)
| "Last seen"  := formatTime("%d-%b-%Y %H:%M:%S", field=_max)

| sort(field=_duration)
```

### Real Example
```cql
// Source: Query-Hub — device_age.yml
// Calculate device age from first to last sensor heartbeat

#event_simpleName=SensorHeartbeat
| in(field=event_platform, values=[?Platform])
| groupBy([aid, ComputerName], function=session([max(@timestamp), min(@timestamp)]))
| "Last seen"  := formatTime("%d-%b-%Y %H:%M:%S", field=_max)
| "First seen" := formatTime("%d-%b-%Y %H:%M:%S", field=_min)
| "Age in h"   := _duration / 3600000
| age := formatDuration(_duration, precision=2)
| "Age in h"   := format(format="%.2f", field=["Age in h"])
| sort(field=_duration)
| drop([@timestamp, _duration, _max, _min])
```

### Pitfalls
- `session()` must be used inside `groupBy()` as an aggregation function
- `_duration`, `_min`, `_max` are auto-generated output fields — don't name your own fields with underscores
- Session boundaries are determined by the time picker range, not by activity gaps (unlike some SIEM session functions)
- For gap-based sessionization, consider `bucket()` or `slidingTimeWindow()` instead

---

## Pattern: Dual-Threshold Spray Detection

**When to use:** Detect credential spraying by requiring BOTH high failure count AND many unique targets/endpoints
**Complexity:** Medium
**Log sources:** Endpoint | Identity
**Requires:** None

### Template
```cql
#event_simpleName=YourLogonFailedEvent
// Aggregate by attacker identifier (username, source IP, etc.)
| groupBy(AttackerKey, function=([
    count(timestamp, distinct=true, as=uniqueFailures),
    count(TargetKey, distinct=true, as=uniqueTargets),
    collect(fields=[TargetKey, ContextField], limit=10000)
  ]))

// Apply dual threshold: high failures AND wide spread
| uniqueFailures >= 5   // Adjust: minimum failure count
| uniqueTargets >= 10   // Adjust: minimum unique targets (endpoints, accounts, etc.)

| sort(uniqueTargets)
```

### Real Example
```cql
// Source: Query-Hub — Failed_logon_attempt.yml
// Detect password spray: user with 5+ failed logons across 10+ unique endpoints

#event_simpleName=UserLogonFailed
| groupBy(UserName, function=([
    count(timestamp, distinct=true, as=uniqueFailedLogons),
    count(aid, distinct=true, as=uniqueEP),
    collect(fields=[ComputerName, aid], limit=10000)
  ]))
| default(field="UserName", value="-", replaceEmpty=true)
| uniqueFailedLogons >= 5
| uniqueEP >= 10
| sort(uniqueEP)
```

### Pitfalls
- Single-threshold detections (just count > N) catch brute force but miss low-and-slow spray attacks
- The dual threshold (failures AND breadth) dramatically reduces false positives from users mistyping passwords
- `count(field, distinct=true)` counts unique values, not total events — essential for spray detection
- Tune both thresholds independently: failure count catches volume, target count catches spread
- Consider adding a time window constraint (via `bucket()` or detection schedule) to prevent historical accumulation
