# LogScale Case Statement Mastery

Case statements are the most critical and error-prone component of LogScale queries. This reference provides comprehensive guidance on proper case statement construction.

## Critical Syntax Rules

**ABSOLUTE REQUIREMENTS:**
1. **Pipe prefix**: Case block MUST start with `|` (pipe character)
2. **Opening brace**: Use `{` immediately after `case` with NO space before it
3. **Condition separator**: Use `|` (pipe) between condition and assignment(s)
4. **Assignment operator**: Use `:=` (colon-equals) for field assignments
5. **Multiple assignments**: Separate with `|` (pipe) within same branch
6. **Branch terminator**: End each branch with `;` (semicolon)
7. **Default branch**: ALWAYS include `* |` default case
8. **Closing brace**: End with `}` on its own or after last semicolon

**STRUCTURAL FORMAT:**
```cql
| case {
    condition1 | field1 := value1 | field2 := value2 ;
    condition2 | field1 := value3 ;
    * | field1 := default ;
}
```

## Platform Limitations & Constraints

**What You CANNOT Do:**
- ❌ Nest case statements inside other case statements
- ❌ Use comparison operators (>, <, >=, <=, !=) without test() wrapper
- ❌ Reference a field created in the same case block's current branch
- ❌ Use parentheses for grouping complex conditions

**What You CAN Do:**
- ✅ Use AND to combine conditions in a case branch (e.g., `field1="a" AND field2 > 5`)
- ✅ Use multiple inline conditions without AND (space-separated = implicit AND)
- ✅ Use `test()` for numeric comparisons (>, <, >=, <=)
- ✅ Use sequential case statements instead of nesting
- ✅ Create temporary fields (prefixed with `_`) for multi-step logic
- ✅ Always include default branch with `*`
- ✅ Call functions within case branches (e.g., `ipLocation()`, `asn()`)
- ✅ Use composite keys (format()) for complex string-based matching

## Case Statement Patterns by Use Case

**Pattern 1: Simple Equality Check**
```cql
// Direct field comparison (no test() needed for =)
| case {
    Status="Active" | _Label := "Currently Active" ;
    Status="Inactive" | _Label := "Not Active" ;
    Status="Suspended" | _Label := "Temporarily Disabled" ;
    * | _Label := "Unknown Status" ;
}
```

**Pattern 2: Numeric Comparisons**
```cql
// MUST use test() for >, <, >=, <=
| case {
    test(FailedLogins > 10) | _Severity := "Critical" ;
    test(FailedLogins > 5) | _Severity := "High" ;
    test(FailedLogins > 2) | _Severity := "Medium" ;
    test(FailedLogins > 0) | _Severity := "Low" ;
    * | _Severity := "None" ;
}
```

**Pattern 3: String Comparisons**
```cql
// Not-equal requires test()
| case {
    test(UserName != "admin") | _IsStandardUser := true ;
    * | _IsStandardUser := false ;
}

// Regex matching (no test() needed)
| case {
    UserName=/^admin.*/ | _AccountType := "Administrator" ;
    UserName=/^svc.*/ | _AccountType := "Service Account" ;
    UserName=/^[a-z]+\.[a-z]+$/ | _AccountType := "Standard User" ;
    * | _AccountType := "Unknown" ;
}
```

**Pattern 4: Multiple Field Assignments**
```cql
// Assign multiple fields in single branch with | separator
| case {
    RiskScore >= 90 | _Level := "Critical" | _Priority := 1 | _Color := "Red" | _Action := "Immediate" ;
    test(RiskScore >= 70) | _Level := "High" | _Priority := 2 | _Color := "Orange" | _Action := "Urgent" ;
    test(RiskScore >= 40) | _Level := "Medium" | _Priority := 3 | _Color := "Yellow" | _Action := "Review" ;
    * | _Level := "Low" | _Priority := 4 | _Color := "Green" | _Action := "Monitor" ;
}
```

**Pattern 5: Comparing Two Fields**
```cql
// ALWAYS use test() when comparing field to field
| case {
    test(LastSuccess > LastFailure) | _SuccessAfterFail := true ;
    test(LastSuccess < LastFailure) | _SuccessAfterFail := false ;
    test(LastSuccess = LastFailure) | _SuccessAfterFail := "Simultaneous" ;
    * | _SuccessAfterFail := "Unknown" ;
}
```

**Pattern 6: Complex Multi-Field Logic (Using Composite Keys)**
```cql
// CORRECT: Use composite keys for multi-field logic
| _Key := format("%s-%s", field=[Protocol, Port])
| case {
    _Key="tcp-22" | _Service := "SSH" ;
    _Key="tcp-3389" | _Service := "RDP" ;
    _Key="tcp-80" | _Service := "HTTP" ;
    _Key="tcp-443" | _Service := "HTTPS" ;
    _Key="udp-53" | _Service := "DNS" ;
    _Key=/tcp-(80|443)/ | _Service := "Web" ;
    * | _Service := "Other" ;
}
```

**Pattern 7: Checking for Field Existence**
```cql
// Use wildcard or test() for null checks
| case {
    ErrorMessage=* | _HasError := true ;
    * | _HasError := false ;
}

// Alternative with test()
| case {
    test(isNull(ErrorMessage)) | _HasError := false ;
    * | _HasError := true ;
}
```

**Pattern 8: Destructive vs Non-Destructive Assignment**
```cql
// DESTRUCTIVE: Overwrites original field
| case {
    Status=1 | Status := "Active" ;
    Status=0 | Status := "Inactive" ;
    * | Status := "Unknown" ;
}
// Original numeric Status is now a string

// NON-DESTRUCTIVE: Creates new field, preserves original
| case {
    Status=1 | _StatusLabel := "Active" ;
    Status=0 | _StatusLabel := "Inactive" ;
    * | _StatusLabel := "Unknown" ;
}
// Original Status field unchanged, new _StatusLabel created
```

## Sequential Case Statements (The Alternative to Nesting)

Since nesting is not allowed, use sequential case statements:

**WRONG - Nested (NOT SUPPORTED):**
```cql
| case {
    UserType="Admin" | case {
        Location="Internal" | Risk := "Low" ;
        Location="External" | Risk := "High" ;
    } ;
}
// ❌ THIS WILL FAIL
```

**BETTER - Using Composite Keys:**
```cql
// Create composite key for complex logic
| _CompositeKey := format("%s-%s", field=[UserType, Location])

// Single case statement with composite logic
| case {
    _CompositeKey="Admin-Internal" | Risk := "Low" ;
    _CompositeKey="Admin-External" | Risk := "High" ;
    _CompositeKey="Standard-External" | Risk := "Medium" ;
    * | Risk := "Low" ;
}
```

## Advanced Patterns

**Pattern 9: Range Checking**
```cql
// Check if value falls within ranges (specific to most specific)
| case {
    test(Port >= 49152) | _PortType := "Dynamic" ;
    test(Port >= 1024) | _PortType := "Registered" ;
    test(Port >= 0) | _PortType := "Well-Known" ;
    * | _PortType := "Invalid" ;
}
```

**Pattern 10: Multi-Condition with Composite Keys**
```cql
// Build composite key from multiple conditions
| case {
    test(FileName=/\.exe$/) | _FileType := "exe" ;
    test(FileName=/\.dll$/) | _FileType := "dll" ;
    test(FileName=/\.(ps1|bat|cmd)$/) | _FileType := "script" ;
    * | _FileType := "other" ;
}
| case {
    test(FileSize > 10000000) | _SizeCategory := "large" ;
    * | _SizeCategory := "normal" ;
}
| case {
    FilePath=/Windows\\Temp/ | _PathCategory := "temp" ;
    * | _PathCategory := "standard" ;
}

// Combine with composite key
| _Key := format("%s-%s-%s", field=[_FileType, _SizeCategory, _PathCategory])
| case {
    _Key="exe-large-standard" | _Suspicious := "Large Executable" ;
    _Key="dll-normal-temp" | _Suspicious := "Temp DLL" ;
    _Key=/^script-.*/ | _Suspicious := "Script File" ;
    * | _Suspicious := "Standard File" ;
}
```

**Pattern 11: Composite Key for Complex Multi-Field Logic**
```cql
// Build composite key from multiple fields
| _Key := format("%s|%s|%s", field=[Protocol, Port, DestIP])

// Use composite key in case statement
| case {
    _Key="tcp|22|0.0.0.0/0" | _Risk := "CRITICAL: SSH to World" | _Score := 100 ;
    _Key="tcp|3389|0.0.0.0/0" | _Risk := "CRITICAL: RDP to World" | _Score := 100 ;
    _Key=/tcp\|(80|443)\|.*/ | _Risk := "Medium: Web Port" | _Score := 40 ;
    * | _Risk := "Low" | _Score := 10 ;
}
```

**Pattern 12: Time-Based Conditions**
```cql
// Extract time components and use in case
| _Hour := formatTime("%H", field=@timestamp)

// Build time category flags
| case {
    test(_Hour >= "22") | _IsLateNight := true ;
    test(_Hour <= "06") | _IsEarlyMorning := true ;
    test(_Hour >= "09") | _IsDaytime := true ;
    test(_Hour <= "17") | _IsBeforeEvening := true ;
    * | _IsOther := true ;
}

// Combine flags with composite key
| _TimeKey := format("%s-%s-%s-%s", field=[_IsLateNight, _IsEarlyMorning, _IsDaytime, _IsBeforeEvening])
| case {
    _TimeKey=/^true-.*/ | _TimeCategory := "After Hours" ;
    _TimeKey=/.*-true-.*/ | _TimeCategory := "After Hours" ;
    _TimeKey="false-false-true-true" | _TimeCategory := "Business Hours" ;
    * | _TimeCategory := "Edge Hours" ;
}
```

## Production Patterns from Real Detections

These patterns are extracted from deployed security detections and demonstrate advanced real-world usage.

**Pattern 13: Handling Missing Baseline Data**
```cql
// From: AWS CloudTrail management activity spike detection
// Purpose: Set threshold to 0 when identity has no historical baseline

| threshold := mgmt_events_average_count + 3 * mgmt_events_std_deviation_count
| case {
    threshold!=* | threshold := 0; // Identity with no activity in the baseline
    *;
}
| test(mgmt_events_total_count > threshold)
```

**What This Demonstrates**:
- Checking for field existence with `!=*` (field does not exist)
- Setting default value when baseline data is missing
- Empty default branch (`*;`) when no assignment needed
- Statistical threshold calculation (mean + 3σ)

**Pattern 14: Multi-Platform Pattern Matching**
```cql
// From: CrowdStrike endpoint suspicious hostname detection
// Purpose: Match default hostname patterns across different operating systems

| case {
    // Windows common default hostname patterns
    event_platform="Win" ComputerName=/^(?:win(?:dows)?|laptop|desktop|pc|srv)-\w+$|\w+-(?:laptop|desktop|pc)$/i;
    // MacOS common default hostname patterns
    event_platform="Mac" ComputerName=/(?:\w+-i?mac|-\w+\.local(domain)?$)/i;
    // Linux (Ubuntu) default hostname patterns
    event_platform="Lin" ComputerName=/(^ubuntu-\w+|-?ubuntu$)/i;
    // Linux (Red Hat/CentOS) default hostname patterns
    event_platform="Lin" ComputerName=/\w+\.localdomain|(?:rhel|centos)-/i;
    // Linux (Debian) default hostname patterns
    event_platform="Lin" ComputerName=/(^debian-\w+|-?debian$)/i;
    // Chrome OS
    event_platform="Lin" ComputerName=/(?:chromebook|chromebox)-/i;
}
```

**What This Demonstrates**:
- Multiple conditions in single branch (field=value + regex match)
- Platform-specific logic with inline comments
- Case-insensitive regex with `/i` flag
- Complex regex patterns with non-capturing groups `(?:...)`
- Alternation within regex patterns `pattern1|pattern2`

**Pattern 15: File Extension Categorization with Comments**
```cql
// From: M365 sensitive file collection detection
// Purpose: Categorize files by type based on extension patterns

| file.extension := lower(file.extension)
| case {
    // Database Files - Database and backup files that might contain structured sensitive data
    file.extension=/(?:sql|db|dbf|mdb|accdb|sqlite|sqlite3|bak|backup|dmp|hdf)$/i;

    // Source Code & Scripts - Programming and scripting files
    file.extension=/(?:rb?|vbs?|tsx?|jsx?|sh|bat|kt|scala|groovy|sql|go|java|cs|php|pl|py|cmd|psm?1|c|cpp|h|hta|ya?ml|ipynb)$/i;

    // Design & Technical Files - CAD, GIS, PLC Config and design files
    file.extension=/(?:dwg|dxf|psd|ai|eps|skp|blend|dxf|stl|iges|pdf\/e|vsdx?|parquet|dec|las|csar|cxp|pod|azm|wic|brd|shp|gdb|geojson|gpkg|tif|dem)$/i;

    // Custom Internal Documents - Company-specific sensitive document patterns
    file.name=/(?<file.confidentiality>CONFIDENTIAL|RESTRICTED|PROPRIETARY|SECRET)/i
}
```

**What This Demonstrates**:
- Field normalization before case statement (`lower()`)
- Category-based detection with descriptive comments
- Optional character matching with `?` (e.g., `rb?` matches `r` or `rb`)
- Named capture groups: `(?<field.name>pattern)` creates new field
- Documenting business logic with inline comments
- Case branches without explicit assignment (just matching)

**Pattern 16: Conditional Enrichment (Operations Within Case Branches)**
```cql
// From: CrowdStrike endpoint suspicious hostname detection
// Purpose: Only enrich external IPs (not RFC1918 private IPs)

| case {
    NOT cidr(aip, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
        | ipLocation(aip)
        | asn(aip);
    *
}
```

**What This Demonstrates**:
- Function calls within case branches (not just assignments!)
- CIDR subnet matching with `cidr()` function
- Negation with `NOT` operator
- Conditional enrichment for performance optimization
- Multiple operations in single branch (ipLocation + asn)
- Empty default branch when no action needed

**Key Insight**: Case branches can contain:
- Field assignments: `field := value`
- Function calls: `ipLocation(field)`, `asn(field)`
- Multiple operations separated by `|`

## Build-Then-Use Pattern (Critical for format() and Other Functions)

**WRONG - Trying to use field in same case block:**
```cql
| case {
    Status="Active" | _Label := "Active" | _Message := format("Status: %s", field=[_Label]) ;
}
// ❌ _Label may not be available yet in format()
```

**CORRECT - Build field first, then use it:**
```cql
// Step 1: Build the field
| case {
    Status="Active" | _Label := "Active" ;
    Status="Inactive" | _Label := "Inactive" ;
    * | _Label := "Unknown" ;
}

// Step 2: Use the field in format()
| _Message := format("Status: %s", field=[_Label])
```

**CORRECT - Alternative with all logic in format():**
```cql
// Do the case logic AND formatting in one step
| case {
    Status="Active" | _Message := format("Status: %s", field=["Active"]) ;
    Status="Inactive" | _Message := format("Status: %s", field=["Inactive"]) ;
    * | _Message := format("Status: %s", field=["Unknown"]) ;
}
```

## Common Errors and Fixes

**Error 1: Missing test() for Comparisons**
```cql
// ❌ WRONG
| case {
    Count > 5 | Level := "High" ;
}

// ✅ CORRECT
| case {
    test(Count > 5) | Level := "High" ;
}
```

**Error 2: AND/OR in Case Branches**
```cql
// ✅ WORKS - AND combines conditions in case branches
| case {
    DetectionTier = "RAPID" AND UniqueIPs > 1 | RiskScore := 90;
    entra.privilege_category="global_admin" AND CountryRisk!="low" | CompositeRiskScore := CompositeRiskScore + 25;
    * | RiskScore := 50;
}

// ✅ ALSO WORKS - Space-separated conditions (implicit AND)
| case {
    event_platform="Win" ComputerName=/^laptop-/i;
    event_platform="Lin" ComputerName=/^ubuntu-/i;
}

// ✅ ALTERNATIVE - Composite key (cleaner for string matching)
| _Key := format("%s-%s", field=[Protocol, Port])
| case {
    _Key="tcp-22" | Service := "SSH" ;
    _Key="tcp-3389" | Service := "RDP" ;
    * | Service := "Other" ;
}
```

**Source**: AND patterns used extensively in production - see `microsoft_entra_id_multiple_failed_login_optimized.yaml` (lines 108-134) and `microsoft_entraid_unauthorized_international_signin.yaml` (lines 58-63)

**Error 3: Missing Semicolons**
```cql
// ❌ WRONG
| case {
    Status="Active" | Label := "Active"
    Status="Inactive" | Label := "Inactive"
}

// ✅ CORRECT
| case {
    Status="Active" | Label := "Active" ;
    Status="Inactive" | Label := "Inactive" ;
}
```

**Error 4: Missing Default Branch**
```cql
// ❌ WRONG (will error if no conditions match)
| case {
    Status="Active" | Label := "Active" ;
    Status="Inactive" | Label := "Inactive" ;
}

// ✅ CORRECT
| case {
    Status="Active" | Label := "Active" ;
    Status="Inactive" | Label := "Inactive" ;
    * | Label := "Unknown" ;
}
```

**Error 5: Wrong Assignment Operator**
```cql
// ❌ WRONG
| case {
    Status="Active" | Label = "Active" ;
}

// ✅ CORRECT
| case {
    Status="Active" | Label := "Active" ;
}
```

**Error 6: Attempting to Nest Case Statements**
```cql
// ❌ WRONG - Nesting case inside case is not supported
| case {
    UserType="Admin" | case { Location="External" | Risk := "High" ; } ;
}

// ✅ CORRECT - Use AND to combine conditions directly in branches
| case {
    UserType="Admin" AND Location="External" | Risk := "High" ;
    UserType="Admin" AND Location="Internal" | Risk := "Low" ;
    * | Risk := "Medium" ;
}

// ✅ ALSO CORRECT - Composite key approach (useful for many combinations)
| _Key := format("%s-%s", field=[UserType, Location])
| case {
    _Key="Admin-External" | Risk := "High" ;
    _Key="Admin-Internal" | Risk := "Low" ;
    * | Risk := "Medium" ;
}
```

> **Note:** AND works directly in case branches. Use it for combining 2-3 conditions.
> For many field combinations, composite keys via `format()` may be more readable.
> See production examples: `crowdstrike___endpoint___potential_privilege_escalation_via_exploit.yaml`,
> `microsoft_entraid_unauthorized_international_signin.yaml`

**Error 7: Missing Pipe Between Condition and Assignment**
```cql
// ❌ WRONG
| case {
    Status="Active" Label := "Active" ;
}

// ✅ CORRECT
| case {
    Status="Active" | Label := "Active" ;
}
```

**Error 8: Using != Without test()**
```cql
// ❌ WRONG
| case {
    Status != "Active" | Label := "Not Active" ;
}

// ✅ CORRECT
| case {
    test(Status != "Active") | Label := "Not Active" ;
}
```

## Case Statement Debugging Workflow

**Step 1: Test with Simple Assignment**
```cql
// Start with simplest possible case
| case {
    Status="Active" | _Test := "Works" ;
    * | _Test := "Default" ;
}
| table([Status, _Test])
```

**Step 2: Add One Condition at a Time**
```cql
// Add complexity incrementally
| case {
    Status="Active" | _Test := "Active" ;
    Status="Inactive" | _Test := "Inactive" ;  // Add this
    * | _Test := "Default" ;
}
```

**Step 3: Add Multiple Assignments**
```cql
// Add additional field assignments
| case {
    Status="Active" | _Test := "Active" | _Score := 100 ;
    Status="Inactive" | _Test := "Inactive" | _Score := 0 ;
    * | _Test := "Default" | _Score := 50 ;
}
```

**Step 4: Add Complex Logic**
```cql
// Add test() for comparisons
| case {
    test(Status="Active" AND Score > 50) | _Test := "High Active" ;
    Status="Active" | _Test := "Active" ;
    * | _Test := "Default" ;
}
```

**Step 5: Validate Output**
```cql
// Always validate with table
| table([Status, Score, _Test, _Score])
```

## Decision Tree for Case Statement Construction

```
Do you need to compare values (>, <, >=, <=, !=)?
├─ YES → Use test()
│  └─ test(Field1 > Field2) | Assignment := value ;
└─ NO → Check what type of condition
   ├─ Simple equality (=)?
   │  └─ Field="value" | Assignment := value ;
   ├─ Regex match?
   │  └─ Field=/pattern/ | Assignment := value ;
   ├─ Multiple conditions (AND/OR)?
   │  └─ test(Cond1 AND Cond2) | Assignment := value ;
   └─ Field existence?
      └─ Field=* | Assignment := value ;

Do you need to assign multiple fields?
├─ YES → Separate with | (pipe)
│  └─ Condition | Field1 := val1 | Field2 := val2 ;
└─ NO → Single assignment
   └─ Condition | Field := value ;

Do you need nested logic?
├─ YES → Use SEQUENTIAL case statements (not nested)
│  ├─ First case: Create intermediate fields
│  └─ Second case: Use intermediate fields
└─ NO → Single case statement

Always include:
├─ Default branch: * | Field := default_value ;
├─ Branch terminator: Semicolon (;) at end
└─ Validation: | table([relevant_fields])
```

## Performance Considerations

**Efficient Case Ordering:**
```cql
// Put most common conditions first
| case {
    Status="Active" | Label := "Active" ;           // 80% of cases
    Status="Inactive" | Label := "Inactive" ;       // 15% of cases
    Status="Suspended" | Label := "Suspended" ;     // 4% of cases
    * | Label := "Unknown" ;                        // 1% of cases
}
```

**Avoid Redundant Case Statements:**
```cql
// ❌ INEFFICIENT - Multiple passes
| case { Type="A" | _TypeA := true ; * | _TypeA := false ; }
| case { Type="B" | _TypeB := true ; * | _TypeB := false ; }
| case { Type="C" | _TypeC := true ; * | _TypeC := false ; }

// ✅ EFFICIENT - Single pass
| case {
    Type="A" | _Category := "TypeA" ;
    Type="B" | _Category := "TypeB" ;
    Type="C" | _Category := "TypeC" ;
    * | _Category := "Other" ;
}
```

## Testing Checklist

Before finalizing any case statement, verify:

- [ ] Starts with `|` pipe character
- [ ] Opening `{` immediately after `case`
- [ ] Each condition has `|` before assignment(s)
- [ ] All assignments use `:=` operator
- [ ] Multiple assignments separated by `|`
- [ ] Each branch ends with `;` semicolon
- [ ] Default branch `* |` is present
- [ ] All comparisons (>, <, >=, <=, !=) wrapped in `test()`
- [ ] AND/OR conditions used correctly in branches (AND works directly, no nesting needed)
- [ ] No nested case statements (use AND in a single branch instead)
- [ ] Fields used in later statements are created in earlier ones
- [ ] Tested with sample data using `| table()`
- [ ] Closing `}` is present
