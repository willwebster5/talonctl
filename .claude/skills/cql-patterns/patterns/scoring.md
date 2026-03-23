# Scoring Patterns

Patterns for assigning risk scores, severity tiers, and threat classifications to events.
Reach for these when a binary "alert / no alert" is not enough — you need graduated severity,
composite risk scoring, or multi-hypothesis classification.

## Pattern: Weighted case{} Scoring

**When to use:** Assign numeric risk weights to specific behaviors and sum them for a composite score
**Complexity:** Medium
**Log sources:** Endpoint
**Requires:** None

### Template
```cql
#event_simpleName=ProcessRollup2
// Replace with your filter criteria

// Assign behavior weights via case{}
| case {
    ConditionA AND SubConditionA1 | behaviorWeight := "25";  // Critical behavior
    ConditionA AND SubConditionA2 | behaviorWeight := "10";   // High-risk behavior
    ConditionB                    | behaviorWeight := "4";    // Medium behavior
    ConditionC                    | behaviorWeight := "3";    // Low behavior
    *                                                         // No match = no weight
}
| default(field=behaviorWeight, value=1)

// Aggregate per entity and time bucket
| groupby([aid, dayBucket], function=[
    count(FileName, distinct=true, as="fileCount"),
    sum(behaviorWeight, as="behaviorWeight"),
    series(executionDetails)
  ], limit=max)

// Apply composite threshold
| fileCount >= 5 OR behaviorWeight > 30  // Adjust for your environment
```

### Real Example
```cql
// Source: Query-Hub — Detect_Suspicious_Windows_Command-Line_Activity_Using_System_Utilities.yml
// Score system utility usage with context-aware weighting

#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\(?<FileName>(whoami|net1?|systeminfo|ping|nltest|sc|hostname|ipconfig)\.exe)/i
| ProcessStartTime := ProcessStartTime*1000
| dayBucket := formatTime("%Y-%m-%d %H", field=ProcessStartTime, locale=en_US, timezone=Z)
| CommandLine := lower(CommandLine)
| FileName := lower(FileName)
| regex("(sc|net1?)\s+(?<netFlag>\S+)\s+", field=CommandLine, strict=false)
| netFlag := lower(netFlag)
| case {
    FileName=/net1?\.exe/ AND netFlag="stop" AND CommandLine=/falcon/i | behaviorWeight := "25";
    FileName=/sc\.exe/ AND netFlag=/(query|stop)/i AND CommandLine=/csagent/i | behaviorWeight := "25";
    FileName=/net1?\.exe/ AND netFlag="user" AND CommandLine=/\/add/i | behaviorWeight := "10";
    FileName=/net1?\.exe/ AND netFlag="localgroup" AND CommandLine=/\/add/i | behaviorWeight := "10";
    FileName=/net1?\.exe/ AND netFlag="group" AND CommandLine=/admin/i | behaviorWeight := "5";
    FileName=/net1?\.exe/ AND netFlag="start" | behaviorWeight := "4";
    FileName=/nltest\.exe/ | behaviorWeight := "3";
    FileName=/whoami\.exe/ | behaviorWeight := "3";
    *
}
| default(field=behaviorWeight, value=1)
| format(format="(Score: %s) %s - %s", field=[behaviorWeight, FileName, CommandLine], as="executionDetails")
| groupby([cid, aid, dayBucket], function=[
    count(FileName, distinct=true, as="fileCount"),
    sum(behaviorWeight, as="behaviorWeight"),
    series(executionDetails)
  ], limit=max)
| fileCount >= 5 OR behaviorWeight > 30
| sort(behaviorWeight)
```

### Pitfalls
- `case{}` evaluates top-to-bottom and takes the FIRST match — put the most specific/severe conditions first
- `behaviorWeight` as string "25" is coerced to integer by `sum()` — this is intentional CQL behavior
- A `*` fallback with no assignment means unmatched events get no weight field — use `default()` to handle this
- The composite threshold (fileCount OR behaviorWeight) catches both diversity-based and severity-based anomalies
- Time bucketing via `dayBucket` prevents cross-day accumulation from inflating scores

---

## Pattern: Severity Tiering with Temporal Gating

**When to use:** Multi-tier detection with RAPID/STANDARD/SUSTAINED severity levels and duplicate-prevention gating
**Complexity:** Complex
**Log sources:** Identity | Any
**Requires:** Scheduled detection (tiers reference the detection's execution schedule)

### Template
```cql
// Replace with your event filter
#Vendor="your_vendor" #event.outcome="failure"

// Aggregate per entity with temporal context
| groupBy([entity.key], function=[
    count(as=TotalFailures),
    min(@timestamp, as=FirstAttempt),
    max(@timestamp, as=LastAttempt),
    count(source.ip, as=UniqueIPs, distinct=true)
  ])

// Calculate timing
| _current_time := now()
| AttackDurationMinutes := (LastAttempt - FirstAttempt) / 60000

// Pre-calculate velocity (arithmetic inside case{} doesn't work)
| _velocity_calc := TotalFailures / AttackDurationMinutes
| _failures_15m_ratio := TotalFailures * 15 / AttackDurationMinutes

// Estimate failures in time windows
| case {
    AttackDurationMinutes > 0 | AttackVelocity := _velocity_calc;
    * | AttackVelocity := TotalFailures;
}
// Assign detection tier
| case {
    Failures_15m >= 3 | DetectionTier := "RAPID"     | Severity := 70;
    Failures_30m >= 5 | DetectionTier := "STANDARD"   | Severity := 50;
    TotalFailures >= 8 | DetectionTier := "SUSTAINED" | Severity := 40;
    * | Severity := 0;
}
| Severity > 0

// Temporal gating: prevent duplicate alerts across detection runs
| _alert_window_ms := 20 * 60 * 1000  // schedule + grace period
| _cutoff_time := _current_time - _alert_window_ms
| test(LastAttempt > _cutoff_time)
```

### Real Example
```cql
// Source: TUNING_PATTERNS.md — Pattern #14, Multi-Tier Failed Login Detection
// Three-tier failed login detection with velocity scoring and duplicate prevention

#Vendor="microsoft" #event.dataset=/entraid/ #repo!="xdr*"
| array:contains(array="event.category[]", value="authentication")
| #event.kind="event" #event.outcome="failure"
| error.code=50126 user.name=*
| groupBy([user.name], function=[
    count(_event_id, as=TotalFailures, distinct=true),
    min(@timestamp, as=FirstAttempt),
    max(@timestamp, as=LastAttempt),
    count(source.ip, as=UniqueIPs, distinct=true),
    collect([source.ip], limit=10),
    count(Vendor.properties.appDisplayName, as=UniqueApps, distinct=true)
  ])
| _current_time := now()
| AttackDurationMinutes := (LastAttempt - FirstAttempt) / 60000
| _velocity_calc := TotalFailures / AttackDurationMinutes
| _failures_15m_ratio := TotalFailures * 15 / AttackDurationMinutes
| case {
    AttackDurationMinutes > 0 | AttackVelocity := _velocity_calc;
    * | AttackVelocity := TotalFailures;
}
| case {
    Failures_15m >= 3 | DetectionTier := "RAPID"     | Severity := 70 | ConfidenceLevel := "High";
    Failures_30m >= 5 | DetectionTier := "STANDARD"   | Severity := 50 | ConfidenceLevel := "Medium";
    TotalFailures >= 8 | DetectionTier := "SUSTAINED" | Severity := 40 | ConfidenceLevel := "Medium";
    * | DetectionTier := "BELOW_THRESHOLD" | Severity := 0;
}
| Severity > 0
| _alert_window_ms := 20 * 60 * 1000
| _cutoff_time := _current_time - _alert_window_ms
| test(LastAttempt > _cutoff_time)
| case {
    UniqueIPs > 1 AND UniqueApps > 2 | AttackPattern := "Multi-Application Spray";
    UniqueIPs > 1 | AttackPattern := "Distributed/Multiple Sources";
    AttackVelocity > 1.0 | AttackPattern := "High-Velocity Attack";
    * | AttackPattern := "Single Source/Standard";
}
```

### Pitfalls
- Arithmetic inside `case{}` branches does NOT work in CQL — pre-calculate values before the case statement
- Temporal gating window = detection schedule + grace period (e.g., 15m schedule + 5m grace = 20m window)
- `now()` returns current time at query execution — not event time
- RAPID/STANDARD/SUSTAINED tiers should be tuned per environment; the thresholds above are starting points
- Extended lookback (1h) provides context; temporal gating prevents duplicate alerts from the same events

---

## Pattern: slidingTimeWindow + rulesHit

**When to use:** N-of-M composite risk scoring across independent signals on the same event type
**Complexity:** Medium
**Log sources:** Any (single event type)
**Requires:** None

### Template
```cql
#event_simpleName=YourEventType
// Collect fields needed for scoring into sliding windows
| slidingTimeWindow(function=[
    collect([Field1, Field2], multival=false)
  ], window=15m, slide=5m)    // Adjust window and slide for your use case

// Assign per-condition flags (0 or 1)
| rule1 := if(Field1=/pattern1/, then=1, else=0)
| rule2 := if(Field2=/pattern2/, then=1, else=0)
| rule3 := if(Field2=/pattern3/, then=1, else=0)
| rule4 := if(Field1=/pattern4/, then=1, else=0)

// Sum rules hit and apply N-of-M threshold
| rulesHit := rule1 + rule2 + rule3 + rule4
| rulesHit >= 2  // Fire when N+ conditions met
```

### Real Example
```cql
// Source: query-patterns.md — slidingTimeWindow + rulesHit N-of-M Scoring
// Detect suspicious process launch: fire when any 3 of 5 indicators present

#event_simpleName=ProcessRollup2
| slidingTimeWindow(function=[collect([ImageFileName, CommandLine])], window=10m, slide=2m)
| s1 := if(ImageFileName=/\\(powershell|cmd|wscript|cscript)\.exe$/i, then=1, else=0)
| s2 := if(CommandLine=/-enc\s+[A-Za-z0-9+\/]{20}/i, then=1, else=0)
| s3 := if(CommandLine=/http[s]?:\/\//i, then=1, else=0)
| s4 := if(CommandLine=/-noprofile|-nop\b/i, then=1, else=0)
| s5 := if(CommandLine=/iex|invoke-expression/i, then=1, else=0)
| score := s1 + s2 + s3 + s4 + s5
| score >= 3
```

### Pitfalls
- Use `slidingTimeWindow` (not `correlate()`) when all signals come from the SAME event type
- `window` is the total window size; `slide` is how far it advances — smaller slide = more overlap = fewer missed clusters
- `multival=false` in `collect()` keeps the last value per field; use `multival=true` for array collection
- `if()` returns integers for arithmetic; regex patterns must be valid CQL regex syntax
- N-of-M approach is resilient to evasion: attacker must suppress multiple indicators simultaneously

---

## Pattern: Multi-Hypothesis case{}

**When to use:** Classify events into distinct threat hypotheses for parallel investigation tracks
**Complexity:** Medium
**Log sources:** Any
**Requires:** None

### Template
```cql
// Start with a broad filter or no filter
| case {
    // Hypothesis 1: Most specific/severe first
    #event_simpleName=EventA AND Condition1 AND Condition2
    AND NOT (ExclusionCondition)
    | hunt_hypothesis := "H1_HYPOTHESIS_NAME";

    // Hypothesis 2: Different TTP
    #event_simpleName=EventB AND Condition3
    | hunt_hypothesis := "H2_HYPOTHESIS_NAME";

    // Hypothesis 3: Persistence variant
    #event_simpleName=EventA AND PersistenceCondition
    | hunt_hypothesis := "H3_HYPOTHESIS_NAME";

    // Catch-all: exclude non-matches
    * | hunt_hypothesis := "NO_MATCH";
}
| hunt_hypothesis != "NO_MATCH"
| select([@timestamp, hunt_hypothesis, ComputerName, UserName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

### Real Example
```cql
// Source: Query-Hub — hunting_bitsadmin_usage.yml
// Four-hypothesis BITS abuse detection: direct exec, PowerShell, persistence, proxy recon

| case {
    #event_simpleName=ProcessRollup2
    AND (ImageFileName=/\\bitsadmin\.exe$/i OR OriginalFilename="bitsadmin.exe")
    AND (CommandLine=/\/transfer/i OR CommandLine=/\/addfile/i OR CommandLine=/\/download/i
         OR CommandLine=/\/SetNotifyCmdLine/i OR CommandLine=/https?:\/\//i)
    AND NOT (ParentBaseFileName=svchost.exe OR ParentBaseFileName=msiexec.exe)
    | hunt_hypothesis := "H1_BITSADMIN_DIRECT_EXEC";

    #event_simpleName=ScriptControlScanV2 OR #event_simpleName=CommandHistory
    AND (ScriptContent=/Start-BitsTransfer/i OR ScriptContent=/BITS\.IBackgroundCopyManager/i)
    AND (ScriptContent=/https?:\/\//i OR ScriptContent=/\-Source/i)
    | hunt_hypothesis := "H2_POWERSHELL_BITSTRANSFER";

    #event_simpleName=ProcessRollup2
    AND (CommandLine=/SetNotifyCmdLine/i OR CommandLine=/SetMinRetryDelay/i)
    AND NOT CommandLine=/Windows.Update/i
    | hunt_hypothesis := "H3_BITS_PERSISTENCE";

    #event_simpleName=ProcessRollup2
    AND ImageFileName=/\\bitsadmin\.exe$/i AND CommandLine=/getieproxy/i
    | hunt_hypothesis := "H4_BITS_PROXY_RECON";

    * | hunt_hypothesis := "NO_MATCH";
}
| hunt_hypothesis != "NO_MATCH"
| select([@timestamp, hunt_hypothesis, ComputerName, UserName, ImageFileName, CommandLine,
          ParentBaseFileName, ScriptContent, SHA256HashData])
| sort(@timestamp, order=desc)
```

### Pitfalls
- `case{}` takes FIRST match — order hypotheses from most specific to least specific
- The `NO_MATCH` catch-all followed by a filter removes uninteresting events efficiently
- Different hypotheses can match different event types (ProcessRollup2, ScriptControlScanV2, etc.)
- Use `select()` not `table()` for output — `select()` preserves all rows; `table()` limits to 200
- Each hypothesis should map to a distinct TTP or attack stage for actionable triage
