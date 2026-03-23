# Baselining Patterns

Patterns for establishing "normal" behavior and detecting deviations. Reach for these when
your detection needs to answer "is this unusual?" rather than "did this specific thing happen?"

## Pattern: neighbor() for Sequential Analysis

**When to use:** Compare consecutive events per entity to detect impossible travel, velocity changes, or state transitions
**Complexity:** Medium
**Log sources:** Identity | Network
**Requires:** Events pre-sorted by entity + timestamp (via groupBy)

### Template
```cql
#event_simpleName=YourEventType
// Pre-aggregate to get one row per entity per event
| groupBy([EntityHash, Timestamp], function=[collect([Field1, Field2])], limit=max)

// Get geolocation or other enrichment
| ipLocation(IPField)

// Pull previous row's fields for comparison
| neighbor([Timestamp, IPField, IPField.country, IPField.lat, IPField.lon],
    prefix=prev)

// Ensure sequential events belong to the same entity
| test(EntityHash == prev.EntityHash)

// Calculate delta between consecutive events
| TimeDelta := (Timestamp - prev.Timestamp) * 1000  // Adjust units as needed
| TimeDelta := round(TimeDelta)

// Apply anomaly threshold
| test(CalculatedMetric > Threshold)
```

### Real Example
```cql
// Source: Query-Hub — Impossible_Travel_Time_Azure.yml
// Detect impossible travel between consecutive Azure SSO logins

in(field="#event_simpleName", values=[SsoApplicationAccess, SsoUserLogon])
| ClientUserAgentString!=/ios |Android|Safari/i
| !cidr(SourceEndpointAddressIP4, subnet=["0.0.0.0/16"])  // Exclude proxy CIDRs
| SourceIP:=concat([SourceEndpointAddressIP4, SourceEndpointAddressIP6])
| UserHash:=concat([SourceAccountUserName, SourceAccountAzureId])
| UserHash:=crypto:md5([UserHash])
| groupBy([UserHash, ContextTimeStamp], function=[collect([SourceAccountUserName,
    SourceIP, ISPDomain, ClientUserAgentString, SourceEndpointHostName])], limit=max)
| ipLocation(SourceIP)
| neighbor([ContextTimeStamp, SourceIP, ISPDomain, UserHash, SourceIP.country,
    SourceIP.lat, SourceIP.lon, SourceEndpointHostName, ClientUserAgentString],
    prefix=prev)
| test(UserHash == prev.UserHash)
| LogonDelta := (ContextTimeStamp - prev.ContextTimeStamp) * 1000
| TimeToTravel := formatDuration(LogonDelta, precision=2)
| DistanceKm := (geography:distance(lat1="SourceIP.lat", lat2="prev.SourceIP.lat",
    lon1="SourceIP.lon", lon2="prev.SourceIP.lon")) / 1000
| DistanceKm := round(DistanceKm)
| SpeedKph := DistanceKm / (LogonDelta / 1000 / 60 / 60) | SpeedKph := round(SpeedKph)
| test(SpeedKph > 900)
| test(SourceIP.country != prev.SourceIP.country)
```

### Pitfalls
- `neighbor()` requires data to be sorted — run `groupBy` with timestamp as a key first
- Always `test(EntityHash == prev.EntityHash)` to prevent false positives at sequence boundaries
- The first event per entity has no previous row — `prev.*` fields will be null
- `neighbor()` only looks at the immediately preceding row; for multi-hop analysis, chain multiple calls
- Proxy/VPN traffic creates false positives — exclude known proxy CIDRs with `!cidr()`

---

## Pattern: Time-Window Baseline Comparison

**When to use:** Compare recent behavior (last 24h) against a historical baseline (7d+) to detect anomalies
**Complexity:** Medium
**Log sources:** Endpoint
**Requires:** Search time range must cover both baseline and recent periods

### Template
```cql
#event_simpleName=YourEventType
// Calculate the metric you want to baseline
| MetricValue := length("CommandLine")  // Replace with your metric
| MetricValue > 0

// Classify events into historical vs recent windows
| case {
    test(@timestamp < (end() - duration(7d))) | DataSet := "Historical";
    test(@timestamp > (end() - duration(1d))) | DataSet := "LastDay";
    *
}

// Calculate per-entity averages for each window
| groupBy([DataSet, EntityKey], function=avg(MetricValue))
| case {
    DataSet="Historical" | rename(field="_avg", as="historicalAvg");
    DataSet="LastDay"    | rename(field="_avg", as="todaysAvg");
    *
}

// Merge and calculate deviation
| groupBy([EntityKey], function=[avg("historicalAvg", as=historicalAvg),
    avg("todaysAvg", as=todaysAvg)])
| PercentIncrease := (todaysAvg - historicalAvg) / historicalAvg * 100

// Filter to significant deviations
| PercentIncrease > 0  // Adjust threshold for your environment
| sort(PercentIncrease, limit=10000)
```

### Real Example
```cql
// Source: Query-Hub — Hunting_Powershell_Command_Length_Anomaly.yml
// Detect anomalous PowerShell command length increases (indicator of obfuscation/encoding)

#event_simpleName=ProcessRollup2
| ImageFileName=/\\(powershell(_ise)?|pwsh)\.exe/i
| CommandLength := length("CommandLine") | CommandLength > 0
| case {
    test(@timestamp < (end() - duration(7d))) | DataSet := "Historical";
    test(@timestamp > (end() - duration(1d))) | DataSet := "LastDay";
    *
}
| groupBy([DataSet, aid], function=avg(CommandLength))
| case {
    DataSet="Historical" | rename(field="_avg", as="historicalAvg");
    DataSet="LastDay"    | rename(field="_avg", as="todaysAvg");
    *
}
| groupBy([aid], function=[avg("historicalAvg", as=historicalAvg),
    avg("todaysAvg", as=todaysAvg)])
| PercentIncrease := (todaysAvg - historicalAvg) / historicalAvg * 100
| format("%d", field=PercentIncrease, as=PercentIncrease)
| format(format="%.2f", field=[historicalAvg], as=historicalAvg)
| PercentIncrease > 0
| sort(PercentIncrease, limit=10000)
```

### Pitfalls
- Search time range in the time picker MUST cover both windows (e.g., 8d+ for a 7d baseline + 1d recent)
- `end()` returns the end of the search time range, NOT current time — this is critical for correctness
- `duration()` creates a millisecond duration value for time arithmetic
- Events in the gap between historical and recent windows (days 2-6) are dropped by the case statement — this is intentional
- Hosts with no historical data get no baseline — `PercentIncrease` will be null; filter or handle explicitly
- Short baselines (1-3d) are noisy; 7d captures weekly patterns; 30d catches monthly cycles

---

## Pattern: $createBaseline Functions

**When to use:** Apply pre-built baseline functions to detect first-time or anomalous behavior over standard windows
**Complexity:** Simple
**Log sources:** Any
**Requires:** Deployed saved search functions ($create_baseline_7d, $create_baseline_60d, $create_baseline_90d)

### Template
```cql
// Replace with your event filter
#Vendor="your_vendor" event.action=YourAction

// Apply a baseline window — creates _baseline_* fields
| $create_baseline_7d()     // 7-day baseline
// OR
| $create_baseline_60d()    // 60-day baseline
// OR
| $create_baseline_90d()    // 90-day baseline

// The function adds context about whether this entity/action was seen in the baseline period
// Use the output fields to filter or score
```

### Real Example
```cql
// Detect first-time AWS API calls per identity using a 7-day baseline
// (Our internal pattern — no external source)

(#repo="cloudtrail" OR #repo="fcs_csp_events") #Vendor="aws"
| $aws_enrich_user_identity()
| $create_baseline_7d()
// Filter to actions not seen in the 7-day baseline for this identity
// Score or alert based on novelty
```

### Pitfalls
- These are our internally deployed saved search functions — they must be deployed via `resource_deploy.py`
- Each baseline function has a fixed lookback window matching its name (7d, 60d, 90d)
- The detection's time picker range must be >= the baseline window for the function to have historical data
- Longer baselines (60d, 90d) require more memory and run slower — use 7d for most detections
- First-time-seen detections are noisy in new environments; pair with enrichment to filter expected onboarding activity

---

## Pattern: geography:distance()

**When to use:** Calculate physical distance between two geolocated events for impossible travel or location anomaly detection
**Complexity:** Simple
**Log sources:** Identity | Network (events with IP addresses)
**Requires:** `ipLocation()` enrichment applied first to get lat/lon fields

### Template
```cql
// Enrich IPs with geolocation first
| ipLocation(CurrentIP)
| ipLocation(PreviousIP)  // Or use neighbor() to get the previous event's IP

// Calculate distance in meters, convert to km
| DistanceKm := geography:distance(
    lat1="CurrentIP.lat", lat2="PreviousIP.lat",
    lon1="CurrentIP.lon", lon2="PreviousIP.lon") / 1000
| DistanceKm := round(DistanceKm)

// Calculate required travel speed
| TimeDeltaHours := TimeDeltaMs / 1000 / 60 / 60
| SpeedKph := DistanceKm / TimeDeltaHours
| SpeedKph := round(SpeedKph)

// Threshold: faster than commercial aviation = impossible
| test(SpeedKph > 900)
```

### Real Example
```cql
// Source: Query-Hub — Impossible_Travel_Time_Azure.yml
// Calculate distance and speed between consecutive logins

| ipLocation(SourceIP)
| neighbor([ContextTimeStamp, SourceIP, SourceIP.country, SourceIP.lat, SourceIP.lon], prefix=prev)
| test(UserHash == prev.UserHash)
| LogonDelta := (ContextTimeStamp - prev.ContextTimeStamp) * 1000
| DistanceKm := (geography:distance(lat1="SourceIP.lat", lat2="prev.SourceIP.lat",
    lon1="SourceIP.lon", lon2="prev.SourceIP.lon")) / 1000
| DistanceKm := round(DistanceKm)
| SpeedKph := DistanceKm / (LogonDelta / 1000 / 60 / 60)
| SpeedKph := round(SpeedKph)
| test(SpeedKph > 900)
| test(SourceIP.country != prev.SourceIP.country)
| Travel := format(format="%s -> %s", field=[prev.SourceIP.country, SourceIP.country])
| format("%,.0f km", field=["DistanceKm"], as="DistanceKm")
| format("%,.0f km/h", field=["SpeedKph"], as="SpeedKm/h")
```

### Pitfalls
- `geography:distance()` returns meters — divide by 1000 for kilometers
- Requires lat/lon from `ipLocation()` — always call ipLocation first
- Private IPs have no geolocation; distance calculation returns 0 or null
- VPN/proxy traffic produces false positives — exclude known proxy CIDRs before distance calculation
- The 900 km/h threshold (commercial aviation speed) is a common starting point; adjust for your risk tolerance
- Same-country travel with different cities can still trigger — add `test(country1 != country2)` to reduce noise
