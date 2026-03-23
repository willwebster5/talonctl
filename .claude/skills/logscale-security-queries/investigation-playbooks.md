# Investigation Playbooks and Hunting Methodology

Structured approaches for security investigation and threat hunting.

## Investigation Philosophy

Effective security investigations follow a structured methodology that progresses through logical phases:
1. **Triage** - Quick overview of suspicious activity
2. **Context Gathering** - Enrich events with user/system details
3. **Timeline Analysis** - Establish sequence of events
4. **Lateral Movement** - Identify spread patterns
5. **Root Cause** - Find initial compromise

## Five-Phase Investigation Framework

### Phase 1: Triage (Immediate Visibility)

**Goal**: Get a quick overview of suspicious activity to determine if deeper investigation is warranted.

**Query Pattern**:
```cql
// Quick count of suspicious indicators
#event_simpleName=<EventType>
| suspicious_indicators_present
| groupBy([UserID, SourceIP], function=[count(), dc(<relevant_field>)])
| sort(_count, order=desc, limit=20)
| case {
    test(_count > 50) | _Severity := "Critical" ;
    test(_count > 20) | _Severity := "High" ;
    test(_count > 10) | _Severity := "Medium" ;
    * | _Severity := "Low" ;
}
```

**Example - Failed Login Triage**:
```cql
#event_simpleName=UserLogonFailed
| groupBy([UserPrincipalName, SourceIP], function=[count()])
| test(_count > 3)
| sort(_count, order=desc, limit=20)
| case {
    test(_count > 10) | _Urgency := "Immediate" ;
    test(_count > 5) | _Urgency := "High" ;
    * | _Urgency := "Standard" ;
}
```

### Phase 2: Context Gathering

**Goal**: Enrich suspicious events with user, system, and location context.

**Query Pattern**:
```cql
// Add all available context
<suspicious_events_from_phase1>
| match(file="entraidusers.csv", field=UserPrincipalName, include=[DisplayName, Department, Title])
| ipLocation(SourceIP)
| join({aid_master}, field=aid, include=[ComputerName, OU, OSVersion])
```

**Example - User Context Enrichment**:
```cql
#event_simpleName=PrivilegeEscalation
| match(file="entraidusers.csv", field=UserPrincipalName, include=[DisplayName, Department, Manager])
| ipLocation(SourceIP)

// Build risk flags
| case {
    test(Department != "IT") | _DeptFlag := "NonIT" ;
    * | _DeptFlag := "IT" ;
}
| case {
    test(Country != "US") | _GeoFlag := "International" ;
    * | _GeoFlag := "Domestic" ;
}

// Combine flags
| _RiskKey := format("%s-%s", field=[_DeptFlag, _GeoFlag])
| case {
    _RiskKey="NonIT-International" | _ContextRisk := "High" ;
    _RiskKey="NonIT-Domestic" | _ContextRisk := "Medium" ;
    * | _ContextRisk := "Low" ;
}
```

### Phase 3: Timeline Analysis

**Goal**: Establish the sequence of events and identify patterns over time.

**Query Pattern**:
```cql
// Create timeline with formatted timestamps
<enriched_events_from_phase2>
| _TimestampEST := formatTime("%Y-%m-%d %H:%M:%S", field=@timestamp, timezone="America/New_York")
| _Hour := formatTime("%H", field=@timestamp)
| _Date := formatTime("%Y-%m-%d", field=@timestamp)
| sort(@timestamp)
| tail(100)
```

**Example - Attack Timeline**:
```cql
// Build complete timeline of user activity
#event_simpleName=*
| aid=<suspicious_aid_from_earlier_phases>
| _TimestampEST := formatTime("%Y-%m-%d %H:%M:%S", field=@timestamp, timezone="America/New_York")
| case {
    #event_simpleName=ProcessRollup2 | _EventCategory := "Process" ;
    #event_simpleName=NetworkConnectIP4 | _EventCategory := "Network" ;
    #event_simpleName=FileWritten | _EventCategory := "File" ;
    * | _EventCategory := "Other" ;
}
| sort(@timestamp)
| table([_TimestampEST, _EventCategory, #event_simpleName, <key_details>])
```

### Phase 4: Lateral Movement Detection

**Goal**: Identify if the threat has spread to other systems or accounts.

**Query Pattern**:
```cql
// Find related activity across systems
<suspicious_user_or_process_from_phase3>
| groupBy([UserID], function=[collect([TargetHost, TargetIP, TargetService])])
| test(length(_TargetHost) > 5)
| case {
    test(length(_TargetHost) > 20) | _Spread := "Widespread" | _Priority := "Critical" ;
    test(length(_TargetHost) > 10) | _Spread := "Moderate" | _Priority := "High" ;
    * | _Spread := "Limited" | _Priority := "Medium" ;
}
```

**Example - Cross-Host Activity**:
```cql
// Track user activity across multiple systems
#event_simpleName=UserLogon
| UserPrincipalName=<suspicious_user>
| groupBy([UserPrincipalName], function=[dc(ComputerName), collect(ComputerName)])
| test(_dc_ComputerName > 3)
| case {
    test(_dc_ComputerName > 10) | _LateralMovement := "Extensive" | _Action := "Contain immediately" ;
    test(_dc_ComputerName > 5) | _LateralMovement := "Moderate" | _Action := "Isolate systems" ;
    * | _LateralMovement := "Limited" | _Action := "Monitor closely" ;
}
```

### Phase 5: Root Cause Analysis

**Goal**: Find the initial compromise or entry point.

**Query Pattern**:
```cql
// Find earliest suspicious event
<all_related_events>
| sort(@timestamp, order=asc)
| head(50)
| case {
    #event_simpleName=/.*Download.*|.*Written.*/ | _VectorType := "File-based" ;
    #event_simpleName=/.*NetworkConnect.*/ | _VectorType := "Network-based" ;
    #event_simpleName=/.*Logon.*/ | _VectorType := "Credential-based" ;
    * | _VectorType := "Unknown" ;
}
```

**Example - Initial Access Identification**:
```cql
// Find first malicious activity for a user
#event_simpleName=*
| UserPrincipalName=<compromised_user>
| @timestamp >= <incident_timeframe_start>
| @timestamp <= <incident_timeframe_end>
| sort(@timestamp, order=asc)
| head(10)
| _TimestampEST := formatTime("%Y-%m-%d %H:%M:%S", field=@timestamp, timezone="America/New_York")
| case {
    SourceIP=/^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/ | _InitialAccess := "Internal" ;
    * | _InitialAccess := "External" ;
}
```

## Specific Investigation Playbooks

### Playbook: Compromised User Account

**Phase 1: Verify Compromise**
```cql
#event_simpleName=UserLogon
| UserPrincipalName=<suspected_user>
| ipLocation(SourceIP)
| groupBy([SourceIP, Country], function=[count()])
```

**Phase 2: Identify Scope**
```cql
#event_simpleName=*
| UserPrincipalName=<compromised_user>
| @timestamp >= <compromise_time>
| groupBy([#event_simpleName], function=[count()])
| sort(_count, order=desc)
```

**Phase 3: Check for Data Access**
```cql
#event_simpleName=FileRead OR #event_simpleName=FileWritten
| UserPrincipalName=<compromised_user>
| case {
    FileName=/\.xlsx$|\.docx$|\.pdf$/ | _FileType := "Document" | _Sensitivity := "High" ;
    FileName=/\.zip$|\.rar$/ | _FileType := "Archive" | _Sensitivity := "Critical" ;
    * | _FileType := "Other" | _Sensitivity := "Low" ;
}
```

**Phase 4: Identify Persistence**
```cql
#event_simpleName=ScheduledTaskRegister OR #event_simpleName=ServiceInstalled
| UserPrincipalName=<compromised_user>
```

### Playbook: Malware Investigation

**Phase 1: Initial Detection**
```cql
#event_simpleName=ProcessRollup2
| ImageFileName=<suspicious_process>
| groupBy([aid], function=[count(), min(@timestamp)])
| join({aid_master}, field=aid, include=[ComputerName, OU])
```

**Phase 2: Process Ancestry**
```cql
#event_simpleName=ProcessRollup2
| aid=<infected_aid>
| @timestamp >= <infection_timeframe>
| case {
    ParentImageFileName=/.*(explorer|cmd|powershell).*/ | _Suspicious := "High" ;
    * | _Suspicious := "Review" ;
}
```

**Phase 3: Network Indicators**
```cql
#event_simpleName=NetworkConnectIP4
| aid=<infected_aid>
| @timestamp >= <infection_timeframe>
| ipLocation(RemoteIP)
| case {
    test(Country != "US") | _C2Likelihood := "High" ;
    test(RemotePort > 49152) | _C2Likelihood := "Medium" ;
    * | _C2Likelihood := "Low" ;
}
```

**Phase 4: File Modifications**
```cql
#event_simpleName=FileWritten
| aid=<infected_aid>
| @timestamp >= <infection_timeframe>
| case {
    TargetDirectory=/Windows\\Temp|AppData\\Local\\Temp/ | _Suspicious := "High" ;
    FileName=/\.(exe|dll|ps1)$/ | _Suspicious := "High" ;
    * | _Suspicious := "Medium" ;
}
```

### Playbook: Insider Threat

**Phase 1: Anomalous Behavior**
```cql
#event_simpleName=FileRead
| UserPrincipalName=<suspected_insider>
| groupBy([FileName], function=[count()])
| test(_count > 100)
| case {
    FileName=/salary|payroll|confidential/i | _DataType := "Sensitive" ;
    FileName=/\.sql$|\.db$/ | _DataType := "Database" ;
    * | _DataType := "Standard" ;
}
```

**Phase 2: Exfiltration Check**
```cql
#event_simpleName=FileWritten
| UserPrincipalName=<suspected_insider>
| TargetDirectory=/removable|external|USB/
| groupBy([TargetDirectory], function=[sum(FileSize), count()])
```

**Phase 3: After-Hours Activity**
```cql
#event_simpleName=*
| UserPrincipalName=<suspected_insider>
| _Hour := formatTime("%H", field=@timestamp)

// Filter to after hours (late night or early morning)
| case {
    test(_Hour >= "22") | _IsAfterHours := true ;
    test(_Hour <= "06") | _IsAfterHours := true ;
    * | _IsAfterHours := false ;
}
| _IsAfterHours=true
| groupBy([#event_simpleName], function=[count()])
```

### Playbook: Privilege Escalation

**Phase 1: Detect Escalation**
```cql
#event_simpleName=AssumeRole OR #event_simpleName=RoleAssignment
| aws_service_account_detector(userIdentity.principalId)
| _AccountType = "Human User"
| case {
    requestedPrivileges=/Admin|Root/ | _EscalationLevel := "Critical" ;
    requestedPrivileges=/PowerUser|Elevated/ | _EscalationLevel := "High" ;
    * | _EscalationLevel := "Medium" ;
}
```

**Phase 2: Verify Authorization**
```cql
// Check if user should have these privileges
<escalation_events>
| match(file="entraidusers.csv", field=UserPrincipalName, include=[Department, Title])

// Build authorization flags
| case {
    Department = "IT" | _DeptFlag := "IT" ;
    * | _DeptFlag := "NonIT" ;
}
| case {
    Title=/Admin|Engineer/ | _TitleFlag := "Technical" ;
    * | _TitleFlag := "NonTechnical" ;
}

// Combine flags
| _AuthKey := format("%s-%s", field=[_DeptFlag, _TitleFlag])
| case {
    _AuthKey="IT-Technical" | _Authorized := "Likely" ;
    _AuthKey="NonIT-Technical" | _Authorized := "Unlikely" | _Action := "Immediate review" ;
    _AuthKey="NonIT-NonTechnical" | _Authorized := "Unlikely" | _Action := "Immediate review" ;
    * | _Authorized := "Unknown" | _Action := "Verify with manager" ;
}
```

**Phase 3: Actions Taken**
```cql
// What did they do with elevated privileges?
#event_simpleName=*
| UserPrincipalName=<escalated_user>
| @timestamp >= <escalation_time>
| case {
    #event_simpleName=/Delete|Remove|Disable/ | _ActionType := "Destructive" | _Risk := "Critical" ;
    #event_simpleName=/Create|Add|Modify/ | _ActionType := "Modification" | _Risk := "High" ;
    * | _ActionType := "Read" | _Risk := "Low" ;
}
```

## Investigation Best Practices

1. **Start broad, narrow focus** - Begin with overview queries, then drill down based on findings
2. **Document findings** - Use comments to note what you've discovered and why it matters
3. **Preserve timestamps** - Always format timestamps for investigation notes
4. **Think attacker mindset** - What would you do next if you were the attacker?
5. **Check for cleanup** - Look for log deletion, file removal, account deletion
6. **Validate assumptions** - Don't assume first finding is root cause
7. **Consider business context** - Is this activity normal for this user/department?
8. **Track IOCs** - Document all indicators of compromise for future detection

## Investigation Query Structure

```cql
// ============================================
// INVESTIGATION: <Brief Description>
// DATE: <Investigation Date>
// ANALYST: <Your Name>
// ============================================

// PHASE 1: TRIAGE
// Quick overview of suspicious activity
<triage_query>

// FINDINGS: <What you discovered>
// NEXT STEPS: <What to investigate next>

// ============================================
// PHASE 2: CONTEXT GATHERING
// Enrich with user/system details
<enrichment_query>

// FINDINGS: <What you discovered>
// NEXT STEPS: <What to investigate next>

// ============================================
// PHASE 3: TIMELINE ANALYSIS
// Establish sequence of events
<timeline_query>

// FINDINGS: <What you discovered>
// NEXT STEPS: <What to investigate next>

// ============================================
// PHASE 4: LATERAL MOVEMENT
// Identify spread patterns
<cross_host_query>

// FINDINGS: <What you discovered>
// NEXT STEPS: <What to investigate next>

// ============================================
// PHASE 5: ROOT CAUSE
// Find initial compromise
<root_cause_query>

// FINDINGS: <What you discovered>
// CONCLUSION: <Final assessment>
```

## Common Investigation Patterns

### Pattern: Find Related Activity
```cql
// Given a suspicious IP, find all related activity
<base_event_with_suspicious_ip>
| join({
    #event_simpleName=*
    | SourceIP=<suspicious_ip>
}, field=SourceIP)
```

### Pattern: User Behavior Baseline
```cql
// Compare current activity to user's baseline
#event_simpleName=<EventType>
| UserPrincipalName=<user>
| @timestamp >= <baseline_period_start>
| groupBy([#event_simpleName, _Hour], function=[count()])
| case {
    test(_count > <baseline_avg> * 3) | _Anomaly := "High" ;
    test(_count > <baseline_avg> * 2) | _Anomaly := "Medium" ;
    * | _Anomaly := "Normal" ;
}
```

### Pattern: Pivot on IOC
```cql
// Given one IOC, find all related IOCs
#event_simpleName=*
| <known_ioc_filter>
| groupBy([#event_simpleName], function=[collect([<other_potential_iocs>])])
```
