# Correlation Patterns

Patterns for linking multiple event types or stages into a single detection. Reach for these
when a single event filter is not enough — you need to prove that event A *and* event B (and
maybe C) happened in the same context.

## Pattern: defineTable + readFile Chain

**When to use:** Multi-stage lifecycle detection where each stage produces context consumed by the next
**Complexity:** Complex
**Log sources:** Endpoint
**Requires:** Multiple event types with linkable fields (aid, ProcessId, FilePath)

### Template
```cql
// Stage 1: Find initial indicator and build a named table
defineTable(query={
    #event_simpleName=EventTypeA
    // Replace with your initial filter criteria
    | rename(field="KeyField", as="StageOneKey")
}, include=[StageOneKey, aid, ContextField1], name="StageOne")

// Stage 2: Match next event type against Stage 1 output
| defineTable(query={
    #event_simpleName=EventTypeB
    | match(file="StageOne", field=[aid, LinkField], column=[aid, StageOneKey],
            strict=true, include=[ContextField1])
    | rename(field="OutputField", as="StageTwoResult")
}, include=[StageTwoResult, ContextField1, aid], name="StageTwo")

// Stage 3: Continue chaining as needed
| defineTable(query={
    #event_simpleName=EventTypeC
    | match(file="StageTwo", field=[aid, LinkField], column=[aid, StageTwoResult],
            strict=true, include=[ContextField1])
}, include=[*], name="StageThree")

// Merge all stages into a single result set
| readFile(["StageOne", "StageTwo", "StageThree"])
```

### Real Example
```cql
// Source: Query-Hub — Charon_Ransomware_Detection_and_Correlation.yml
// Detect Charon ransomware lifecycle: file write -> DLL sideload -> deployment -> ransom note

defineTable(query={#event_simpleName=/Written|PeFileWritten/iF
  | case{
    in(field="SHA256HashData", values=["f3c8b4986377b5a32c20fc665b0cbe0c44153369dadbcaa5e3d0e3c8545e4ba5",
      "e0a23c0d99c45d40f6ef99c901bacf04bb12e9a3a15823b663b392abadd2444e"])
      | rename(field="SHA256HashData", as="RansomeSHA256")
      | Analysis:="Ransomware Package written to disk";
    FileName=/msedge.dll|TSMSISrv.dll|Pulseinternal applicationX96311.dll/iF
      | rename(field="FileName", as="RansomewareFileWritten")
      | Analysis:="Ransomware Package written to disk";
  }
  | groupBy([FilePath, ComputerName], function=([collect([RansomeSHA256, RansomewareFileWritten, Analysis], limit=200000),
    count(RansomewareFileWritten, distinct=true, as=FileCount)]))
  | FileCount>1
}, include=[FilePath, FileCount, ComputerName, RansomeSHA256, RansomewareFileWritten, Analysis], name="RansomeFileWritten")

| defineTable(query={
  #event_simpleName=/ClassifiedModuleLoad/iF
  | (TargetImageFileName=/\\Edge.exe/iF) and (FileName=/msedge.dll|TSMSISrv.dll/iF)
  | rename(field="TargetProcessId", as="PID")
  | Analysis:="Malicious DLL has been sideloaded"
}, include=[PID, Analysis], name="DLLSideLoad")

| defineTable(query={#event_simpleName=/ProcessRollup2/iF
  | match(file="DLLSideLoad", field=[aid, ParentProcessId], column=[aid, PID], strict=true, include=[PID])
  | rename(field="FileName", as="ChildProcess")
}, include=[ChildProcess, PID], name="RansomwareDeploy")

| readFile(["RansomeFileWritten", "DLLSideLoad", "RansomwareDeploy"])
```

### Pitfalls
- Each `defineTable` runs as an independent subquery; the search time range applies to all of them
- `match(strict=true)` drops events with no match — use `strict=false` if you want left-join behavior
- `readFile` merges tables but does NOT deduplicate — columns from different tables may be sparse
- Tables are held in memory; keep `include=[...]` lists tight to avoid quota exhaustion
- Order of `defineTable` declarations matters: you can only `match()` against a table defined earlier

---

## Pattern: correlate() Sequence

**When to use:** Behavioral detection requiring ordered events within a time window across 2+ event types
**Complexity:** Medium
**Log sources:** Any
**Requires:** Shared correlation key across event types (aid, user.email, IP, etc.)

### Template
```cql
correlate(
    StepOne: {
        // Replace with first event filter
        #event_simpleName=EventTypeA
        FieldFilter=value
    } include: [aid, ContextField1],
    StepTwo: {
        // Replace with second event filter
        #event_simpleName=EventTypeB
        | aid <=> StepOne.aid
        | LinkField <=> StepOne.ContextField1
    } include: [aid, ResultField],
    StepThree: {
        // Replace with third event filter (optional — add as many as needed)
        #event_simpleName=EventTypeC
        | aid <=> StepOne.aid
    } include: [aid, FinalField],
    sequence=true,     // Enforce chronological order
    within=30m         // Adjust time window for your detection
)
// Post-correlate analysis
| table([StepOne.ContextField1, StepTwo.ResultField, StepThree.FinalField])
```

### Real Example
```cql
// Source: Query-Hub — cve_2025_53770___sharepoint_toolshell.yml
// Detect webshell deployment: w3wp.exe -> cmd.exe -> powershell.exe -> .aspx file write

correlate(
    cmd: {
        #event_simpleName=ProcessRollup2 event_platform=Win
        FileName="cmd.exe" ParentBaseFileName="w3wp.exe"
    } include: [aid, ComputerName, TargetProcessId, ParentBaseFileName, FileName, CommandLine],
    pwsh: {
        #event_simpleName=ProcessRollup2 event_platform=Win FileName="powershell.exe"
        | aid <=> cmd.aid
        | ParentProcessId <=> cmd.TargetProcessId
    } include: [aid, ComputerName, TargetProcessId, ParentBaseFileName, FileName, CommandLine],
    aspx: {
        #event_simpleName=/^(NewScriptWritten|WebScriptFileWritten)$/ event_platform=Win FileName=/\.aspx/i
        | aid <=> cmd.aid
        | ContextProcessId <=> pwsh.TargetProcessId
    } include: [aid, ComputerName, TargetFileName],
    sequence=true, within=5m
)
```

### Pitfalls
- `correlate()` cannot appear after aggregators (`groupBy`, `count`) — it must be the first function
- Results must fit in memory; add specific filters in each query to reduce volume
- `sequence=true` enforces strict ordering — use `sequence=false` if you only need co-occurrence
- Each `<=>` link is scoped to a query pair; different pairs can pivot on different fields
- `globalConstraints` simplifies when ALL queries share the same key, but cannot replace heterogeneous keys

---

## Pattern: readFile Merge

**When to use:** Combine findings from multiple defineTable stages into a unified result for reporting or downstream analysis
**Complexity:** Simple
**Log sources:** Any
**Requires:** Two or more defineTable results to merge

### Template
```cql
// Define multiple investigation tables
defineTable(query={
    // Replace with first event query
    #event_simpleName=EventA
    | groupBy([KeyField], function=[count(as=CountA)])
}, include=[KeyField, CountA], name="FindingA")

| defineTable(query={
    // Replace with second event query
    #event_simpleName=EventB
    | groupBy([KeyField], function=[count(as=CountB)])
}, include=[KeyField, CountB], name="FindingB")

// Merge all findings into one stream
| readFile(["FindingA", "FindingB"])
// Optional: aggregate merged results
| groupBy([KeyField], function=[collect([CountA, CountB])])
```

### Real Example
```cql
// Source: Query-Hub — Dll-Side_Loading_Detection_Query.yml (final aggregation)
// Merge DLL side-loading findings with MOTW (Mark of the Web) URL data

defineTable(query={readFile([DllLoading])
  | groupBy([ProcessStartTime, SusProcessID, ComputerName, UserName],
    function=([collect([FileWriteFile, DLLSideLoadProcess, "DllLoaded Files",
      ModuleLoadTelemetryClassification, SusHash]),
      count("DllLoaded Files", distinct=true, as="DllLoaded Files Count")]), limit=max)
}, include=[ProcessStartTime, SusProcessID, ComputerName, FileWriteFile, UserName,
  DLLSideLoadProcess, "DllLoaded Files", ModuleLoadTelemetryClassification, SusHash,
  "DllLoaded Files Count"], name="Aggregation")

| defineTable(query={#event_simpleName=MotwWritten
  | match(file="Aggregation", field=[ComputerName, FileName], column=[ComputerName, FileWriteFile],
    strict=true, ignoreCase=true, include=[FileWriteFile, DLLSideLoadProcess, SusProcessID])
  | case{
    HostUrl!="" ReferrerUrl!=""
      | FileWriteFileSourceURL:=format(format="Download URL= %s\nReferrer URL= %s", field=[HostUrl, ReferrerUrl]);
    HostUrl!="" | FileWriteFileSourceURL:=format(format="Download URL= %s", field=[HostUrl]);
    *
  }
}, include=[FileWriteFile, FileWriteFileSourceURL, DLLSideLoadProcess], name="MOTW")

| readFile(["Aggregation", "MOTW"])
```

### Pitfalls
- `readFile` creates a UNION, not a JOIN — rows from different tables appear as separate events
- Column names must match if you want to aggregate across tables after the merge
- If tables have different schemas, unmatched fields will be null in rows from the other table
- Memory usage scales with the sum of all table sizes

---

## Pattern: Multi-stage join

**When to use:** Enrich a single event stream with context from multiple related event types via sequential joins
**Complexity:** Medium
**Log sources:** Endpoint
**Requires:** Shared join keys between event types (AuthenticationID, aid+ProcessId)

### Template
```cql
// Start with primary event stream
#event_simpleName=PrimaryEvent
| YourFilter=value

// Join 1: Add user context
| join({#event_simpleName=UserIdentity},
    field=AuthenticationID, include=[UserName])

// Join 2: Add parent process context
| join({#event_simpleName=SyntheticProcessRollup2},
    field=[aid, RawProcessId], include=[SHA256HashData], suffix="Parent")

// Join 3: Add network context (optional)
| join({#event_simpleName=NetworkConnectIP4},
    field=[aid, ContextProcessId], include=[RemoteAddressIP4, RemotePort])

// Output enriched result
| table([aid, UserName, ImageFileName, CommandLine, SHA256HashDataParent, RemoteAddressIP4])
```

### Real Example
```cql
// Source: Query-Hub — Credential_Dumping_Detection.yml
// Detect credential dumping with user and process hash enrichment

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
- Each `join()` only supports two event types (left + right); chain multiple joins for 3+ types
- `join()` uses an inner join by default — events without a match are dropped; use `mode=left` to keep them
- Joins are memory-intensive; filter the primary stream aggressively before joining
- The `suffix` parameter avoids field name collisions when joining tables with overlapping field names
- For correlating 3+ event types, prefer `correlate()` over chained joins for better performance
