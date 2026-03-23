# Output Patterns

Patterns for formatting, displaying, and linking detection results. Reach for these when you
need to present findings to analysts — readable timestamps, deep links into Falcon, human-friendly
sizes, or visual process trees.

## Pattern: table() vs select()

**When to use:** Choose `table()` for formatted dashboards (limited rows); choose `select()` for full result preservation
**Complexity:** Simple
**Log sources:** Any
**Requires:** None

### Template
```cql
// table() — aggregation that limits to 200 rows by default, reorders columns
| table([Field1, Field2, Field3], limit=20000, sortby=Field1, order=desc)

// select() — non-aggregating projection that keeps ALL rows
| select([@timestamp, Field1, Field2, Field3])
```

### Real Example
```cql
// Source: REVIEW-CQL-Queries.md (cs-shadowbq/CQL-Queries)
// table() is an aggregation — it limits output and reorders fields
// select() is a projection — it preserves all rows and field order

// Use table() for dashboard widgets and analyst-facing output
#event_simpleName=ProcessRollup2
| groupBy([aid, ComputerName], function=[count(as=ProcessCount)])
| table([ComputerName, ProcessCount], limit=1000, sortby=ProcessCount, order=desc)

// Use select() for intermediate pipeline steps or when you need all rows
#event_simpleName=ProcessRollup2
| select([@timestamp, aid, ComputerName, FileName, CommandLine])
| sort(@timestamp, order=desc)
```

### Pitfalls
- `table()` default limit is 200 rows — always specify `limit=` for detection outputs
- `table()` is an aggregation; no further pipeline steps can follow it (except `sort` within table params)
- `select()` preserves all rows but does not support `sortby` — pipe to `sort()` separately
- Use `select()` in multi-hypothesis queries where you need every matching event
- `table()` deduplicates rows with identical values across all selected fields

---

## Pattern: format() for Deep Links

**When to use:** Create clickable Falcon UI links (Process Explorer, Host Search) in query results
**Complexity:** Simple
**Log sources:** Endpoint
**Requires:** `aid` and/or `ContextProcessId` / `TargetProcessId` fields

### Template
```cql
// Process Explorer link — opens the process tree for a specific process
| rootURL := "https://falcon.crowdstrike.com/"  // Adjust for your cloud (US-1, US-2, EU-1, Gov)
| format("[Process Explorer](%sgraphs/process-explorer/tree?id=pid:%s:%s)",
    field=["rootURL", "aid", "ContextProcessId"], as="Process Explorer")
| drop([rootURL])

// Host Search link — opens the investigate view for a specific host
| format("[Host Search](https://falcon.crowdstrike.com/investigate/events/en-us/app/eam2/investigate__computer?earliest=-24h&latest=now&computer=*&aid_tok=%s&customer_tok=*)",
    field=["aid"], as="Host Search")

// Detection link — use FalconHostLink field directly
| format("[Detection Link](%s)", field=[FalconHostLink], as="Detection Link")
```

### Real Example (Process Explorer)
```cql
// Source: Query-Hub — hunting_edr_freeze.yml
// Create Process Explorer link for EDR freeze investigation

#event_simpleName=FalconProcessHandleOpDetectInfo FileName="WerFaultSecure.exe"
| GrandparentCommandLine=/\.exe"?\s+\d+\s+\d+$/ OR ParentCommandLine=/\.exe"?\s+\d+\s+\d+$/
| table([@timestamp, aid, ComputerName, ContextProcessId, ProcessLineage])
| rootURL := "https://falcon.crowdstrike.com/"
| format("[Responsible Process](%sgraphs/process-explorer/tree?id=pid:%s:%s)",
    field=["rootURL", "aid", "ContextProcessId"], as="Process Explorer")
| drop([rootURL, ContextProcessId])
```

### Real Example (Host Search)
```cql
// Source: Query-Hub — Detect_Suspicious_Windows_Command-Line_Activity_Using_System_Utilities.yml
// Add Host Search link to suspicious command-line activity results

| groupby([cid, aid, dayBucket], function=[count(FileName, distinct=true, as="fileCount"),
    sum(behaviorWeight, as="behaviorWeight"), series(executionDetails)], limit=max)
| fileCount >= 5 OR behaviorWeight > 30
| format("[Host Search](https://falcon.crowdstrike.com/investigate/events/en-us/app/eam2/investigate__computer?earliest=-24h&latest=now&computer=*&aid_tok=%s&customer_tok=*)",
    field=["aid"], as="Host Search")
```

### Pitfalls
- Markdown link syntax `[text](url)` works in LogScale table output but NOT in all export formats
- Cloud URL varies by region: US-1, US-2, EU-1, Gov — use a variable for portability
- `ContextProcessId` is the process that triggered the event; `TargetProcessId` is the spawned process
- Store the root URL in a variable and `drop()` it after formatting to keep output clean
- Links require `aid` (agent ID) — events without `aid` (cloud events, audit logs) need different link formats

---

## Pattern: unit:convert() for Sizes

**When to use:** Convert byte values to human-readable file sizes (KB, MB, GB, TB)
**Complexity:** Simple
**Log sources:** Endpoint (file write events)
**Requires:** Numeric byte field

### Template
```cql
#event_simpleName=/FileWritten$/
// Convert bytes to appropriate unit with cascading case{}
| case {
    Size >= 1099511627776 | CommonSize := unit:convert(Size, to=T)
      | format("%,.2f TB", field=["CommonSize"], as="CommonSize");
    Size >= 1073741824 | CommonSize := unit:convert(Size, to=G)
      | format("%,.2f GB", field=["CommonSize"], as="CommonSize");
    Size >= 1048576 | CommonSize := unit:convert(Size, to=M)
      | format("%,.2f MB", field=["CommonSize"], as="CommonSize");
    Size > 1024 | CommonSize := unit:convert(Size, to=k)
      | format("%,.3f KB", field=["CommonSize"], as="CommonSize");
    * | CommonSize := format("%,.0f Bytes", field=["Size"]);
}
```

### Real Example
```cql
// Source: Query-Hub — File_Write_Events_with_Human-Readable_File_Sizes.yml
// Display file write events with human-readable sizes

#event_simpleName=/FileWritten$/
| case {
    Size >= 1099511627776 | CommonSize := unit:convert(Size, to=T)
      | format("%,.2f TB", field=["CommonSize"], as="CommonSize");
    Size >= 1073741824 | CommonSize := unit:convert(Size, to=G)
      | format("%,.2f GB", field=["CommonSize"], as="CommonSize");
    Size >= 1048576 | CommonSize := unit:convert(Size, to=M)
      | format("%,.2f MB", field=["CommonSize"], as="CommonSize");
    Size > 1024 | CommonSize := unit:convert(Size, to=k)
      | format("%,.3f KB", field=["CommonSize"], as="CommonSize");
    * | CommonSize := format("%,.0f Bytes", field=["Size"]);
}
| table([@timestamp, aid, ComputerName, FileName, Size, CommonSize])
```

### Pitfalls
- `unit:convert()` target units are single-character: `k` (kilo), `M` (mega), `G` (giga), `T` (tera)
- `case{}` order matters — check largest unit first, smallest last
- `format("%,.2f")` adds comma separators and 2 decimal places for readability
- The `*` fallback handles files under 1KB — display as raw bytes
- `unit:convert()` does simple division (1024-based); it does not auto-select the unit for you

---

## Pattern: formatTime() and formatDuration()

**When to use:** Convert epoch timestamps to human-readable dates, and millisecond durations to readable time spans
**Complexity:** Simple
**Log sources:** Any
**Requires:** Epoch timestamp or duration in milliseconds

### Template
```cql
// Convert epoch timestamp to formatted date
| ReadableTime := formatTime(format="%F %T", field="EpochField")
// Common formats:
//   %F %T         → 2026-03-19 14:30:45
//   %F %T.%L      → 2026-03-19 14:30:45.123  (with milliseconds)
//   %d-%b-%Y %H:%M:%S → 19-Mar-2026 14:30:45
//   %e %b %Y %r   → 19 Mar 2026 02:30:45 PM

// Convert millisecond duration to human-readable format
| ReadableDuration := formatDuration(DurationMs, precision=2)
// Output: "2 hours, 15 minutes" or "3 days, 4 hours"

// Calculate duration between two timestamps
| Duration := (EndTime - StartTime)
| ReadableDuration := formatDuration(Duration, precision=3)
```

### Real Example
```cql
// Source: Query-Hub — soc_efficiency_metrics.yml
// Calculate and display SOC response time metrics

#repo=detections
| in(field="ExternalApiType", values=[Event_UserActivityAuditEvent, Event_EppDetectionSummaryEvent])
| detectID := Attributes.composite_id | detectID := CompositeId
| case{
    ExternalApiType=Event_UserActivityAuditEvent Attributes.update_status=closed
      | response_time := @timestamp;
    ExternalApiType=Event_EppDetectionSummaryEvent | detect_time := @timestamp;
}
| groupBy([detectID], function=([
    min(detect_time, as=FirstDetect),
    min(response_time, as=ResolvedTime)
  ]), limit=200000)
// Calculate durations
| DetectToClose := (ResolvedTime - FirstDetect)
| DetectToClose := formatDuration(field=DetectToClose, precision=3)
// Calculate age of open alerts
| case{
    Attributes.update_status != "closed"
      | Aging := now() - FirstDetect
      | Aging := formatDuration(Aging, precision=2);
    *;
}
// Format timestamps
| FirstDetect := formatTime(format="%F %T", field="FirstDetect")
| ResolvedTime := formatTime(format="%F %T", field="ResolvedTime")
```

### Pitfalls
- `formatTime()` expects epoch MILLISECONDS by default; if your field is in seconds, multiply by 1000 first
- `precision` in `formatDuration()` controls how many time units to show (e.g., precision=2 → "3 days, 4 hours")
- `formatTime()` uses Java SimpleDateFormat patterns, not strftime — but most common patterns overlap
- Timezone defaults to UTC; specify `timezone="America/New_York"` or your preferred zone
- `formatDuration()` returns a string — you cannot do further arithmetic on the result

---

## Pattern: explain:asTable() — Query Profiling

**When to use:** Profile query performance, identify bottlenecks, validate optimization order before deploying to scheduled searches or correlation rules
**Complexity:** Simple
**Log sources:** Any
**Requires:** None — append to any query

### Template
```cql
// Append explain:asTable() to any query to get per-stage performance metrics
<your query here>
| explain:asTable()
```

### Real Example
```cql
// Source: CQF 2026-03-20 — profile an encoded PowerShell hunting query
// Before optimization: 2,860 work units over 7d window

#event_simpleName=ProcessRollup2
| CommandLine=/\-(e(nc|ncodedcommand|ncoded)?)\s+/iF
| groupBy([ComputerName, event_platform], function=([count(CommandLine, distinct=true, as=uniqueCmdLines), count(aid, as=totalExecutions)]), limit=max)
| explain:asTable()

// Output columns: timeMs, eventCount, prefilter info per pipeline stage
// Shows what prefilters the query engine inserts behind the scenes
// After adding event_platform="Win" filter: dropped to 1,100 work units
```

### Workflow
1. Write your query
2. Append `| explain:asTable()`
3. Check `timeMs` column — find the most expensive stages
4. Narrow filters earlier in the pipeline (add tag/field filters before regex/functions)
5. Compare "Work" units in the NG-SIEM UI before and after changes
6. Remove `explain:asTable()` before deploying

### Pitfalls
- **Ad hoc only** — do NOT include in scheduled searches, triggers, or dashboards
- **Not supported with `correlate()`** — cannot profile correlation rules directly; profile each sub-query independently
- Analyzes the **optimized** query (post-interpolation), not your raw CQL — you'll see prefilters the query engine inserts at runtime
- "Work units" in the NG-SIEM UI are the aggregate cost metric — lower is better, but the absolute number is opaque (like AI tokens)
- Use this as the final validation step when building any query destined for a detection rule or scheduled search

---

## Pattern: Process Lineage Tree

**When to use:** Build a visual grandparent-parent-child process tree for analyst-friendly output
**Complexity:** Simple
**Log sources:** Endpoint
**Requires:** Process hierarchy fields (GrandparentImageFileName, ParentImageFileName, ImageFileName)

### Template
```cql
#event_simpleName=YourEventType

// Build visual process tree using format() with newlines and indent characters
| ProcessLineage := format(
    format="%s (%s)\n   -> %s (%s)\n      -> %s (%s)",
    field=[GrandparentImageFileName, GrandparentCommandLine,
           ParentImageFileName, ParentCommandLine,
           ImageFileName, CommandLine])

// Output with lineage
| table([@timestamp, aid, ComputerName, ProcessLineage])
```

### Real Example
```cql
// Source: Query-Hub — hunting_edr_freeze.yml
// Display process hierarchy for EDR freeze detection

#event_simpleName=FalconProcessHandleOpDetectInfo FileName="WerFaultSecure.exe"
| GrandparentCommandLine=/\.exe"?\s+\d+\s+\d+$/
  OR ParentCommandLine=/\.exe"?\s+\d+\s+\d+$/
  OR CommandLine=/\.exe"?\s+\d+\s+\d+$/
| ProcessLineage := format(
    format="%s (%s)\n   -> %s (%s)\n      -> %s (%s)",
    field=[GrandparentImageFileName, GrandparentCommandLine,
           ParentImageFileName, ParentCommandLine,
           ImageFileName, CommandLine])
| table([@timestamp, aid, ComputerName, ContextProcessId, ProcessLineage])
| rootURL := "https://falcon.crowdstrike.com/"
| format("[Responsible Process](%sgraphs/process-explorer/tree?id=pid:%s:%s)",
    field=["rootURL", "aid", "ContextProcessId"], as="Process Explorer")
| drop([rootURL, ContextProcessId])
```

### Pitfalls
- `\n` creates newlines in LogScale table cells — works in the UI but may display as literal `\n` in CSV exports
- Unicode tree characters (e.g., `\u2514` for corner) are not universally supported — stick to ASCII (`->` or `|`)
- Not all events have grandparent fields — use `default()` to handle nulls: `default(field=GrandparentImageFileName, value="[unknown]")`
- Long command lines in the tree make it hard to read — consider truncating with `format("%.100s", field=[CommandLine])`
- Combine with a Process Explorer deep link for interactive investigation
