# LogScale Query Troubleshooting Guide

Comprehensive error catalog and debugging methodology for CrowdStrike LogScale/CQL syntax issues.

## Case Statement Errors (Most Common)

**Error: "Cannot nest case statements"**
```cql
// ❌ WRONG - Attempting to nest
| case {
    X=1 | case { Y=1 | Z := "bad" ; } ;
}

// ✅ CORRECT - Use composite key (BEST approach)
| _Key := format("%s-%s", field=[X, Y])
| case {
    _Key="1-1" | Z := "good" ;
    * | Z := "default" ;
}
```

**Error: "Invalid comparison in case" or "Unexpected token"**
```cql
// ❌ WRONG - Missing test() wrapper
| case {
    FailedAttempts > 5 | Risk := "High" ;
}

// ❌ WRONG - Using != without test()
| case {
    Status != "Active" | Risk := "Review" ;
}

// ✅ CORRECT - All comparisons in test()
| case {
    test(FailedAttempts > 5) | Risk := "High" ;
    test(Status != "Active") | Risk := "Review" ;
}
```

**Error: "Unexpected 'AND'" in older queries (CORRECTED)**

AND and OR **do work** in case statement branches. If you encounter an older error referencing
this, it was likely caused by a different syntax issue. Production detections use AND extensively:

```cql
// ✅ WORKS - AND in case branches
| case {
    Protocol="tcp" AND Port=22 | Service := "SSH" ;
    Protocol="tcp" AND Port=3389 | Service := "RDP" ;
    * | Service := "Other" ;
}

// ✅ WORKS - AND with test() for comparisons
| case {
    test(Score > 50) AND Status="Active" | Priority := "High" ;
    * | Priority := "Normal" ;
}

// ✅ ALSO WORKS - Composite key approach (useful for many combinations)
| _Key := format("%s-%s", field=[Protocol, Port])
| case {
    _Key="tcp-22" | Service := "SSH" ;
    _Key="tcp-3389" | Service := "RDP" ;
    * | Service := "Other" ;
}
```

> Production sources: `crowdstrike___endpoint___potential_privilege_escalation_via_exploit.yaml`,
> `microsoft_entraid_unauthorized_international_signin.yaml`,
> `microsoft_entra_id_multiple_failed_login_optimized.yaml`

**Error: "Missing semicolon" or "Unexpected token"**
```cql
// ❌ WRONG - Missing semicolons at end of branches
| case {
    Status="Active" | Label := "Active"
    Status="Inactive" | Label := "Inactive"
}

// ❌ WRONG - Missing pipe between assignments
| case {
    Status="Active" | Label := "Active" Score := 100 ;
}

// ✅ CORRECT - Proper formatting
| case {
    Status="Active" | Label := "Active" | Score := 100 ;
    Status="Inactive" | Label := "Inactive" | Score := 0 ;
    * | Label := "Unknown" | Score := 50 ;
}
```

**Error: "Field not found" in case statement**
```cql
// ❌ WRONG - Using field created in same branch
| case {
    X=1 | Y := "value" | Z := format("%s", field=[Y]) ;
}

// ✅ CORRECT - Create field first, use in next statement
| case { X=1 | Y := "value" ; * | Y := "default" ; }
| Z := format("%s", field=[Y])

// ✅ ALTERNATIVE - Do all logic in format()
| case {
    X=1 | Z := format("%s", field=["value"]) ;
    * | Z := format("%s", field=["default"]) ;
}
```

**Error: "No matching case branch"**
```cql
// ❌ WRONG - Missing default branch
| case {
    Status="Active" | Label := "Active" ;
    Status="Inactive" | Label := "Inactive" ;
}
// Fails when Status is neither "Active" nor "Inactive"

// ✅ CORRECT - Always include default
| case {
    Status="Active" | Label := "Active" ;
    Status="Inactive" | Label := "Inactive" ;
    * | Label := "Unknown" ;
}
```

**Error: "Invalid assignment operator"**
```cql
// ❌ WRONG - Using = instead of :=
| case {
    Status="Active" | Label = "Active" ;
}

// ✅ CORRECT - Use := for assignments
| case {
    Status="Active" | Label := "Active" ;
}
```

**Error: "Attempting to nest case statements"**
```cql
// ❌ WRONG - Nesting case inside case is not supported
| case {
    UserType="Admin" | case { Location="External" | Risk := "High" ; } ;
}

// ✅ CORRECT - Use AND to combine conditions directly
| case {
    UserType="Admin" AND Location="External" | Risk := "High" ;
    UserType="Admin" AND Location="Internal" | Risk := "Low" ;
    * | Risk := "Medium" ;
}

// ✅ ALSO CORRECT - Composite key for many combinations
| _Key := format("%s-%s", field=[UserType, Location])
| case {
    _Key="Admin-External" | Risk := "High" ;
    _Key="Admin-Internal" | Risk := "Low" ;
    * | Risk := "Medium" ;
}
```

**Error: "Missing pipe between condition and assignment"**
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

**Error: "Using != without test()"**
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

## Format() Function Errors

**Error: "Field not found in format()"**
```cql
// ❌ WRONG - Field doesn't exist yet
| Message := format("User: %s, Status: %s", field=[UserDisplayName, _Status])
| case { Active=true | _Status := "Active" ; }

// ✅ CORRECT - Create fields before using in format()
| case { Active=true | _Status := "Active" ; * | _Status := "Inactive" ; }
| Message := format("User: %s, Status: %s", field=[UserDisplayName, _Status])
```

**Error: "Wrong number of format arguments"**
```cql
// ❌ WRONG - Mismatched placeholders and fields
| Message := format("User: %s, Score: %s", field=[UserName])  // Missing second field

// ✅ CORRECT - Match placeholders to fields
| Message := format("User: %s, Score: %s", field=[UserName, _Score])
```

**Error: "Invalid format field reference"**
```cql
// ❌ WRONG - Not using field= parameter
| Message := format("User: %s", [UserName])

// ✅ CORRECT - Use field= parameter
| Message := format("User: %s", field=[UserName])
```

## Join and Match Errors

**Error: "CSV file not found"**
```cql
// ❌ WRONG - Incorrect file reference
| match(file="users.csv", field=UserName)

// ✅ CORRECT - Use proper file path
| match(file="entraidusers.csv", field=UserPrincipalName, include=[DisplayName], ignoreCase=true)
```

**Error: "Join field not found"**
```cql
// ❌ WRONG - Field name mismatch
| join({subquery}, field=UserId, include=[UserName])
// Fails if subquery doesn't have UserId

// ✅ CORRECT - Verify field exists in both queries
| join({subquery | rename(user_id, as=UserId)}, field=UserId, include=[UserName])
```

## Test() Function Errors

**Error: "Invalid test() syntax"**
```cql
// ❌ WRONG - Using test() with simple equality (unnecessary)
| case {
    test(Status="Active") | Label := "Active" ;  // test() not needed here
}

// ✅ CORRECT - Only use test() when necessary
| case {
    Status="Active" | Label := "Active" ;  // Simple equality, no test() needed
    test(Score > 50) | Label := "High" ;   // Comparison, test() required
}
```

**Error: "test() used outside case statement"**
```cql
// ❌ WRONG - test() in where clause
| test(Score > 50)

// ✅ CORRECT - Use direct comparison in filters
| Score > 50
// Or if in case statement:
| case { test(Score > 50) | _High := true ; }
```

## GroupBy and Aggregation Errors

**Error: "Field not found after groupBy"**
```cql
// ❌ WRONG - Trying to use non-grouped field
| groupBy([UserId], function=[count()])
| table([UserId, UserName])  // UserName not available after groupBy

// ✅ CORRECT - Include needed fields in groupBy or aggregation
| groupBy([UserId, UserName], function=[count()])
| table([UserId, UserName, _count])
```

**Error: "Invalid aggregation function"**
```cql
// ❌ WRONG - Invalid function name
| groupBy([UserId], function=[distinct(SourceIP)])

// ✅ CORRECT - Use dc() for distinct count
| groupBy([UserId], function=[dc(SourceIP)])
```

## Regex Errors

**Error: "Invalid regex pattern"**
```cql
// ❌ WRONG - Unescaped special characters
| FileName=/file.txt/  // Period not escaped

// ✅ CORRECT - Escape special regex characters
| FileName=/file\.txt/
| FileName=/.*\.txt$/  // Match .txt files
```

**Error: "Regex match not working as expected"**
```cql
// ❌ WRONG - Partial match when exact match intended
| UserName=/admin/  // Matches "administrator", "admin", "superadmin"

// ✅ CORRECT - Use anchors for exact matching
| UserName=/^admin$/  // Matches only "admin"
| UserName=/^admin.*/  // Matches "admin" and anything starting with "admin"
```

## Common Logic Errors

**Error: "Case statement not working as expected"**
```cql
// Issue: Order matters - first match wins
// ❌ SUBOPTIMAL - Broad condition first
| case {
    test(Score > 0) | Level := "Has Score" ;      // This matches everything
    test(Score > 50) | Level := "High Score" ;    // This never executes
}

// ✅ CORRECT - Specific conditions first
| case {
    test(Score > 50) | Level := "High Score" ;
    test(Score > 0) | Level := "Has Score" ;
    * | Level := "No Score" ;
}
```

**Error: "Unexpected results from sequential case statements"**
```cql
// Issue: Second case uses wrong field
// ❌ WRONG - Field name mismatch
| case { UserType="Admin" | _IsAdmin := true ; }
| case { IsAdmin=true | AccessLevel := "Elevated" ; }  // Wrong: should be _IsAdmin

// ✅ CORRECT - Consistent field naming
| case { UserType="Admin" | _IsAdmin := true ; * | _IsAdmin := false ; }
| case { _IsAdmin=true | AccessLevel := "Elevated" ; * | AccessLevel := "Standard" ; }
```

## Debugging Methodology

**Step 1: Isolate the Problem**
```cql
// Comment out sections to find the failing part
| case { /* ... */ }
// | case { /* ... */ }  // Comment out second case
// | format(/* ... */)   // Comment out format
```

**Step 2: Use Simple Test Cases**
```cql
// Replace complex logic with simple test
| case {
    // test(ComplexCondition) | Field := "Complex" ;
    * | Field := "Test" ;  // Does basic case work?
}
```

**Step 3: Add Debug Fields**
```cql
// Create debug fields to see intermediate values
| _Debug1 := UserType
| _Debug2 := format("Type: %s", field=[UserType])
| case { /* ... */ }
| table([_Debug1, _Debug2, /* other fields */])
```

**Step 4: Validate Field Existence**
```cql
// Check if fields exist before using
| table([@rawstring])  // See raw event structure
| where FieldName=*    // Filter to events where field exists
```

**Step 5: Test One Branch at a Time**
```cql
// Start with single branch, then add more
| case {
    Status="Active" | Label := "Active" ;
    * | Label := "Default" ;
}
// Verify this works before adding more branches
```

## Quick Reference: When to Use test()

| Scenario | Syntax | test() Required? |
|----------|--------|------------------|
| Equality (=) | `Field="value"` | ❌ No |
| Greater than (>) | `test(Field > 5)` | ✅ Yes |
| Less than (<) | `test(Field < 10)` | ✅ Yes |
| Greater or equal (>=) | `test(Field >= 5)` | ✅ Yes |
| Less or equal (<=) | `test(Field <= 10)` | ✅ Yes |
| Not equal (!=) | `test(Field != "value")` | ✅ Yes |
| Regex match | `Field=/pattern/` | ❌ No |
| AND operator | `CondA AND CondB \| Result := "x" ;` | ❌ No (works directly in branches) |
| OR operator | Use separate branches for each condition | ❌ N/A |
| Field comparison | `test(Field1 > Field2)` | ✅ Yes |
| Field existence | `Field=*` | ❌ No |
| Null check | `test(isNull(Field))` | ✅ Yes (using function) |

**Note**: AND works directly in case branches. For OR logic, use separate branches (first match wins).
Composite keys via `format()` remain useful when dealing with many field combinations.

## Array Operation Errors

**Error: "Unknown function" with objectArray:eval or array:filter**
```cql
// ❌ WRONG - Missing quotes on array name
| objectArray:eval(Vendor.Parameters[], asArray="params[]", var=x, function={ ... })

// ✅ CORRECT - Quote the array field name
| objectArray:eval("Vendor.Parameters[]", asArray="params[]", var=x, function={
    params := format("%s = %s", field=[x.Name, x.Value])
  })
```

**Error: "Field not found" with array operations**
```cql
// ❌ WRONG - Using array result outside its scope
| array:filter(array="items[]", var=y, asArray="filtered[]", function={ y=/pattern/ })
| table([filtered])  // ❌ Not referencing array correctly

// ✅ CORRECT - Reference the array with [] notation
| array:filter(array="items[]", var=y, asArray="filtered[]", function={ y=/pattern/ })
| filtered[0]=*  // Check first element exists
| table([filtered[0]])
```

**Error: writeJson producing unexpected output**
```cql
// ❌ WRONG - Missing wildcard in writeJson
| writeJson("results[]", as=resultJson)

// ✅ CORRECT - Use [*] wildcard to serialize all elements
| writeJson("results[*]", as=resultJson)
```

> Production source: `microsoft_entra_id_suspicious_inbox_forwarding.yaml`,
> `microsoft_entra_id_new_mfa_device_operating_system_observed.yaml`

## defineTable() Errors

**Error: "Unknown error" with defineTable()**
```cql
// ❌ WRONG - Missing required parameters
| defineTable(
    query={ #Vendor="aws" | groupBy([user.name], function=[count()]) },
    name="baseline"
  )

// ✅ CORRECT - Include all required params: query, include, name, start, end
| defineTable(
    query={
        #Vendor="aws" #event.module="cloudtrail"
        | groupBy([user.name], function=[count(as="_baseline_count")])
    },
    include=[user.name, _baseline_count],
    name="my_baseline",
    start=30d,
    end=70m
  )
```

**Error: defineTable baseline not matching current events**
```cql
// ❌ WRONG - Using match() with strict=true (default) drops unmatched events
| match(file="my_baseline", field=[user.name])
// Events not in baseline are silently dropped

// ✅ CORRECT - Use strict=false to keep unmatched events
| match(file="my_baseline", field=[user.name], strict=false)
// Unmatched events have null baseline fields - check with:
| case {
    _baseline_count!=* ;  // User not in baseline (new behavior)
    test(_baseline_count < 10) ;  // User in baseline but infrequent
}
```

**Error: defineTable window overlap with main query**
```cql
// ❌ WRONG - Baseline overlaps with detection window
| defineTable(query={...}, name="t", start=7d, end=0m)  // end=0m overlaps
// Main query: lookback 1h0m

// ✅ CORRECT - Gap between baseline end and main query lookback
| defineTable(query={...}, name="t", start=30d, end=70m)  // 70m gap
// Main query: lookback 1h0m  (70m > 60m ensures no overlap)
```

> Production source: `aws_cloudtrail_kms_anomalous_data_key_generation.yaml`

## selfJoinFilter() and session() Errors

**Error: selfJoinFilter not correlating events**
```cql
// ❌ WRONG - where clauses don't use the flag fields
| case {
    #event_simpleName="UserLogon" | logonEvent := "true" ;
    #event_simpleName="ProcessRollup2" | processEvent := "true" ;
}
| selfJoinFilter(field=[aid], where=[
    { #event_simpleName="UserLogon" },  // ❌ Re-checking original field
    { #event_simpleName="ProcessRollup2" }
])

// ✅ CORRECT - Use the flag fields created in case branches
| selfJoinFilter(field=[aid], where=[
    { logonEvent="true" },
    { processEvent="true" }
])
```

**Error: session() producing unexpected groupings**
```cql
// ❌ WRONG - maxpause too short, splitting related events
| groupBy([aid], function=[session([collect([fields])], maxpause=1m)])

// ✅ CORRECT - Use appropriate maxpause for your event correlation window
| groupBy([aid], function=[
    session(
        [collect([field1, field2]), min(@timestamp, as="startTime"), max(@timestamp, as="endTime")],
        maxpause=15m
    )
])
```

> Production source: `crowdstrike___endpoint___potential_privilege_escalation_via_exploit.yaml`

## Emergency Fixes: Copy-Paste Solutions

**Fix 1: Case statement template that always works**
```cql
| case {
    Field="value1" | Output := "result1" ;
    Field="value2" | Output := "result2" ;
    * | Output := "default" ;
}
```

**Fix 2: Numeric comparison template**
```cql
| case {
    test(Number > 10) | Category := "High" ;
    test(Number > 5) | Category := "Medium" ;
    test(Number > 0) | Category := "Low" ;
    * | Category := "Zero or Negative" ;
}
```

**Fix 3: Composite key template for multi-field logic**
```cql
// Build composite key from multiple fields
| _Key := format("%s-%s", field=[TypeField, Score])

// Use in case statement  
| case {
    _Key=/^TypeA-[5-9][0-9]$/ | Result := "High A" ;
    _Key=/^TypeB-[5-9][0-9]$/ | Result := "High B" ;
    * | Result := "Low" ;
}
```

**Fix 4: Composite key template for complex logic**
```cql
// Build key from multiple fields
| _Key := format("%s-%s-%s", field=[Field1, Field2, Field3])

// Use in case statement
| case {
    _Key="A-B-C" | Result := "Exact Match" ;
    _Key=/^A-.*/ | Result := "Starts with A" ;
    * | Result := "No Match" ;
}
```

## GroupBy Aggregation Errors

**Error: "Unknown error" with named aggregation assignment**
```cql
// ❌ WRONG - Cannot use := assignment inside groupBy function list
| groupBy([UserId], function=[
    ActionSequence := collect(event.action, limit=50),  // ❌ := not valid here
    UserARN := collect(UserARN, distinct=true, limit=1)  // ❌ := not valid here
])

// ❌ ALSO WRONG - as= parameter doesn't work with collect()
| groupBy([UserId], function=[
    collect(event.action, limit=50, as=ActionSequence)  // ❌ as= not supported
])

// ✅ CORRECT - Use unnamed collect, result inherits field name
| groupBy([UserId], function=[
    collect([event.action, UserARN], limit=50),  // Creates 'event.action' array
    count(),
    min(@timestamp, as=FirstSeen),  // as= works for min/max
    max(@timestamp, as=LastSeen)
])
// Then reference the collected field by its original name:
| ActionList := format("%s", field=[event.action])
```

**Key insight**: In `groupBy()`:
- `count()`, `sum()`, `min()`, `max()`, `avg()` support `as=` for naming
- `collect()` does NOT support `as=` or `:=` - use the original field name
- Named assignments (`:=`) are NOT valid inside the function list

**Error: "Unknown error" with count(field, where=condition)**
```cql
// ❌ WRONG - where= parameter not supported in count() inside groupBy
| groupBy([UserId], function=[
    UserTargets := count(Category, where=Category="Users"),  // ❌ where= not valid
    RoleTargets := count(Category, where=Category="Roles")   // ❌ where= not valid
])

// ✅ CORRECT - Create flags before groupBy, then sum them
| case {
    Category="Users" | _isUser := 1;
    Category="Roles" | _isRole := 1;
    * | _isUser := 0 | _isRole := 0;
}
| _isUser := _isUser | default(value=0)
| _isRole := _isRole | default(value=0)
| groupBy([UserId], function=[
    sum(_isUser, as=UserTargets),
    sum(_isRole, as=RoleTargets)
])
```

## Advanced Debugging: Isolating "Unknown Error"

When you get `INVALID: Syntax error: Unknown error`, the error is often in a function call or parameter. Use this systematic approach:

**Step 1: Stash changes and validate original**
```bash
git stash
python scripts/resource_deploy.py validate-query --template <path>
git stash pop
```
If original validates, the error is in your changes.

**Step 2: Test individual components with inline queries**
```bash
# Test defineTable
python scripts/resource_deploy.py validate-query --query 'defineTable(query={...}, ...) | #Vendor="aws"'

# Test function calls
python scripts/resource_deploy.py validate-query --query '#Vendor="aws" | $my_function()'

# Test groupBy syntax
python scripts/resource_deploy.py validate-query --query '#Vendor="aws" | groupBy([field], function=[count()])'
```

**Step 3: Binary search the query**
```cql
// Comment out half the query, validate
// If valid, error is in commented half
// If invalid, error is in remaining half
// Repeat until isolated
```

**Step 4: Test specific syntax patterns**
```bash
# Test named aggregation (often the problem)
python scripts/resource_deploy.py validate-query --query '#Vendor="aws" | groupBy([x], function=[myName := count()])'
# ❌ INVALID - := not allowed in groupBy

# Test unnamed
python scripts/resource_deploy.py validate-query --query '#Vendor="aws" | groupBy([x], function=[count()])'
# ✅ VALID
```

**Common "Unknown error" causes:**
| Pattern | Why It Fails | Fix |
|---------|--------------|-----|
| `myField := collect(...)` in groupBy | := not allowed in function list | Use `collect([field])`, reference by original name |
| `collect(field, as=name)` | as= not supported for collect | Use original field name after groupBy |
| `count(field, where=condition)` | where= not supported | Create boolean flags, use sum() |
| `test(field > 5)` outside case | test() only works in case statements | Use direct comparison: `field > 5` |
| `$undefined_function()` | Function not deployed | Deploy saved search first |
| `table()` mid-pipeline | table() is aggregation, caps at 200 rows and terminates the pipeline | Use `select()` to drop fields without row cap |
| `table([f1,f2])` returns 200 rows when you have thousands | table() hard limit is 200 | Use `select()` + `sort()` separately, or accept the limit for display queries |
