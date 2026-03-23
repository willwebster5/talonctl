# Enrichment Patterns

Patterns for adding context to events — user identity, host details, geolocation, threat
intel lookups. Reach for these when your detection or hunt needs more context than a single
event type provides.

## Pattern: join() for Event Enrichment

**When to use:** Add fields from a second event type using a shared key (AuthenticationID, aid+ProcessId)
**Complexity:** Simple
**Log sources:** Endpoint
**Requires:** Two event types with a common join key

### Template
```cql
// Primary event stream
#event_simpleName=PrimaryEvent
| YourFilter=value

// Enrich with a second event type
| join({#event_simpleName=SecondaryEvent},
    field=SharedKey,             // Replace with your join key
    include=[Field1, Field2],    // Fields to pull from secondary
    mode=left,                   // left = keep unmatched; inner = drop unmatched
    start=1h)                    // How far back to search for matches
```

### Real Example
```cql
// Source: Query-Hub — Credential_Dumping_Detection.yml
// Enrich process execution with user identity and parent process hash

#event_simpleName=ProcessRollup2
| (CommandLine=/mimikatz|procdump|lsass|sekurlsa/i
   OR ImageFileName=/\\(mimikatz|procdump|pwdump)\.exe$/i)
| ParentImageFileName!=/\\(powershell|cmd)\.exe$/i
| join({#event_simpleName=UserIdentity}, field=AuthenticationID, include=[UserName])
| join({#event_simpleName=SyntheticProcessRollup2}, field=[aid, RawProcessId],
    include=[SHA256HashData], suffix="Parent")
| table([aid, UserName, ImageFileName, CommandLine, ParentImageFileName, SHA256HashData])
```

### Pitfalls
- Default join mode is inner — unmatched events are silently dropped; use `mode=left` to preserve them
- `start` controls the lookback window for the right-side query; too short = missed matches, too long = slow
- `suffix` parameter is required when left and right sides share field names (e.g., both have SHA256HashData)
- Each join adds memory pressure; filter your primary stream before joining, not after

---

## Pattern: selfJoinFilter()

**When to use:** Correlate two event types that share a Falcon UPID (aid + TargetProcessId/ContextProcessId)
**Complexity:** Medium
**Log sources:** Endpoint
**Requires:** Events sharing aid + process identifier (UPID pattern)

### Template
```cql
// Combine two event types in one query
(#event_simpleName=EventTypeA OR #event_simpleName=EventTypeB)

// Normalize the process identifier across event types
| falconPID := TargetProcessId | falconPID := ContextProcessId

// Require both event types to exist for the same aid + process
| selfJoinFilter(field=[aid, falconPID],
    where=[
        {#event_simpleName=EventTypeA},
        {#event_simpleName=EventTypeB}
    ])

// Aggregate the correlated results
| groupBy([aid, falconPID], function=[collect([FieldA, FieldB])])
```

### Real Example
```cql
// Source: Query-Hub — DNS_Resolutions_from_Browser_Processes.yml
// Correlate browser process execution with DNS requests under the same UPID

(#event_simpleName=ProcessRollup2 OR #event_simpleName=DnsRequest) event_platform=Win
| fileName:=concat([FileName, ContextBaseFileName])
| in(field="fileName", values=[chrome.exe, firefox.exe, msedge.exe], ignoreCase=true)
| falconPID:=TargetProcessId | falconPID:=ContextProcessId
| selfJoinFilter(field=[aid, falconPID],
    where=[{#event_simpleName=ProcessRollup2}, {#event_simpleName=DnsRequest}])
| groupBy([aid, falconPID], function=([collect([ComputerName, UserName, fileName, DomainName])]))
```

### Real Example (Port Scanning Detection)
```cql
// Source: Query-Hub — systems_initiating_connections_to_a_high_number_of_ports.yml
// Correlate network connections with process execution to find port scanners

#event_simpleName=/^(NetworkConnectIP4|ProcessRollup2)$/
| falconPID:=TargetProcessId | falconPID:=ContextProcessId
| UserID:=UserSid | UserID:=UID
| selfJoinFilter(field=[aid, falconPID],
    where=[{#event_simpleName=NetworkConnectIP4}, {#event_simpleName=ProcessRollup2}])
| groupBy([aid, ComputerName, falconPID], function=([
    collect([FileName, CommandLine, UserName, UserID]),
    count(RemotePort, as=uniquePortCount),
    count(RemoteAddressIP4, distinct=true, as=remoteIPcount)
  ]), limit=max)
| test(uniquePortCount>25)
```

### Pitfalls
- Both event types must be included in the initial filter with OR — `selfJoinFilter` does not fetch them
- The normalized field (e.g., `falconPID`) must be set for BOTH event types before calling selfJoinFilter
- `prefilter=true` can improve performance when one event type is much rarer than the other
- `selfJoinFilter` is for same-process correlation; for cross-process or cross-host, use `correlate()`

---

## Pattern: match() with CSV Lookup

**When to use:** Enrich events by matching a field against an uploaded CSV (threat intel, allowlists, asset inventories)
**Complexity:** Simple
**Log sources:** Any
**Requires:** CSV file uploaded to LogScale as a lookup file

### Template
```cql
#event_simpleName=YourEventType
// Match against uploaded CSV
| match(file="your-lookup.csv",
    field=EventField,          // Field in your event to match on
    column=CsvColumn,          // Column in the CSV to match against
    include=[EnrichField1, EnrichField2],  // CSV columns to add to events
    strict=true)               // true = inner join, false = left join
// Continue with enriched data
| groupBy([EventField, EnrichField1], function=[count()])
```

### Real Example (Threat Intel)
```cql
// Source: Query-Hub — connections_to_tor_exit_nodes.yml
// Match network connections against a Tor exit node IP list

#event_simpleName=NetworkConnectIP4
| match(file="tor-exit-nodes.csv", field=RemoteAddressIP4, column=ip, strict=true)
| groupBy([aid, ComputerName], function=[
    count(aid, as=ConnectionCount),
    count(aid, distinct=true, as=UniqueIPs),
    collect([RemoteAddressIP4, RemotePort]),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)
  ])
| sort(ConnectionCount, order=desc)
```

### Real Example (Allowlist)
```cql
// Source: Query-Hub — detection_of_generic_user_account_usage.yml
// Detect logons using generic/shared accounts via CSV lookup

#event_simpleName=UserLogon
| user.name := lower("user.name")
| groupBy(user.name, ComputerName)
| match(file="generic-usernames.csv", field=[user.name], column=[username])
| table([user.name, ComputerName, _count])
```

### Pitfalls
- CSV must be uploaded to LogScale before use — deploy via `resource_deploy.py` or console
- `strict=true` drops events with no CSV match (like INNER JOIN); use `strict=false` for LEFT JOIN
- CSV column names are case-sensitive
- Large CSVs (100K+ rows) can slow queries; keep lookup files focused
- `match()` supports multi-field matching: `field=[f1, f2], column=[c1, c2]`

---

## Pattern: IP Enrichment Chain

**When to use:** Add full geographic, network, and DNS context to an IP address
**Complexity:** Simple
**Log sources:** Any (events with IP fields)
**Requires:** None (built-in functions)

### Template
```cql
// Replace "source.ip" with your IP field name
| asn(field=source.ip)
| ipLocation(field=source.ip)
| rdns(field=source.ip)
| geohash(lat=source.ip.lat, lon=source.ip.lon, precision=4)

// Handle missing values
| default(field=asn.org, value="Unknown ASN")
| default(field=source.ip.country, value="Unknown Country")
| default(field=rdns, value="No rDNS")

// Build unified summary field
| ipDetails := format("%s | %s, %s | ASN: %s | rDNS: %s",
    field=[source.ip, source.ip.city, source.ip.country, asn.org, rdns])
```

### Real Example
```cql
// Source: query-patterns.md — IP Enrichment Chain
// Full enrichment chain for endpoint external IP (aip field)

| asn(field=aip)
| ipLocation(field=aip)
| rdns(field=aip)
| geohash(lat=aip.lat, lon=aip.lon, precision=4)
| default(field=asn.org, value="Unknown ASN")
| default(field=aip.country, value="Unknown Country")
| default(field=rdns, value="No rDNS")
| ipDetails := format("%s | %s, %s | ASN: %s | rDNS: %s",
    field=[aip, aip.city, aip.country, asn.org, rdns])
```

### Pitfalls
- Run IP enrichment AFTER `groupBy()` so functions execute once per unique IP, not per raw event
- `ipLocation()` and `asn()` add multiple sub-fields (e.g., `field.country`, `field.city`, `field.lat`)
- `rdns()` can be slow on high-volume queries — consider omitting for dashboards
- `geohash()` requires lat/lon from `ipLocation()` — call ipLocation first
- Private IPs (10.x, 172.16-31.x, 192.168.x) return no geolocation data

---

## Pattern: $falcon/helper:enrich()

**When to use:** Convert numeric CrowdStrike field codes into human-readable labels
**Complexity:** Simple
**Log sources:** Endpoint
**Requires:** None (built-in Falcon function)

### Template
```cql
#event_simpleName=YourEventType
// Replace FieldName with the numeric field to enrich
| $falcon/helper:enrich(field=FieldName)
```

### Real Example
```cql
// Source: Query-Hub — Failed_User_Logon_Thresholding.yml
// Enrich LogonType and SubStatus numeric codes in failed logon events

event_platform=Win #event_simpleName=UserLogonFailed2
| SubStatus_hex:=format(field=SubStatus, "%x")
| SubStatus_hex:=upper(SubStatus_hex)
| SubStatus_hex:=format(format="0x%s", field=[SubStatus_hex])
| groupBy([aid, ComputerName, UserName, LogonType, SubStatus_hex, SubStatus],
    function=([count(aid, as=FailCount),
      min(ContextTimeStamp, as=FirstLogonAttempt),
      max(ContextTimeStamp, as=LastLogonAttempt)]))
| FailCount > 5
| sort(FailCount, order=desc, limit=2000)
// Convert numeric codes to human-readable labels
| $falcon/helper:enrich(field=LogonType)
| $falcon/helper:enrich(field=SubStatus)
```

### Pitfalls
- Only works with known CrowdStrike enumeration fields (LogonType, SubStatus, ProductType, etc.)
- Must be called AFTER aggregation if the field is used in `groupBy` — enriching before changes the value
- Not a general-purpose enrichment tool; it maps specific integer codes to labels
- Returns the original value unchanged if no mapping exists

---

## Pattern: aid_master Enrichment

**When to use:** Add host context (ComputerName, OS, domain, OU, site) to events that only have an `aid`
**Complexity:** Simple
**Log sources:** Any (events with `aid` field)
**Requires:** Access to `aid_master_main.csv` or `$falcon/investigate:aid_base()` saved search

### Template
```cql
#event_simpleName=YourEventType
// Option A: match against aid_master CSV (faster, static snapshot)
| match(file="aid_master_main.csv", field=[cid, aid])

// Option B: join against live aid_base function (real-time, slower)
| join({
    $falcon/investigate:aid_base()
    | groupBy(aid, function=selectLast([ComputerName, MachineDomain, OU, SiteName]), limit=max)
  }, field=aid, include=[ComputerName, MachineDomain, OU, SiteName], mode=left, start=12h)
```

### Real Example
```cql
// Source: Query-Hub — Host_Contained.yml
// Enrich containment audit events with host details via aid_base join

#repo=detections EventType="Event_ExternalApiEvent"
  ExternalApiType="Event_UserActivityAuditEvent" OperationName=containment_requested
| rename(field=AgentIdString, as=aid)
| join({
    $falcon/investigate:aid_base()
    | groupBy(aid, function=selectLast([MachineDomain, OU, SiteName, ComputerName]), limit=max)
  }, field=aid, include=[MachineDomain, OU, SiteName, ComputerName], mode=left, start=12h)
| default(field=[ComputerName, MachineDomain, OU, SiteName], value="--", replaceEmpty=true)
```

### Pitfalls
- `aid_master_main.csv` is a static snapshot — it may lag behind recent sensor installations
- `$falcon/investigate:aid_base()` is real-time but requires a `start` lookback and more memory
- Always use `mode=left` to preserve events even when the aid is not found in aid_master
- Use `selectLast()` in the groupBy to get the most recent host record when multiple exist
- `default(replaceEmpty=true)` handles both null and empty string values
