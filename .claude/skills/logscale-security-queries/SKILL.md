---
name: logscale-security-queries
description: Develop, optimize, and troubleshoot CrowdStrike LogScale (Humio) security detection queries using CQL syntax. Use when writing LogScale queries, building security detections, creating threat hunting rules, fixing CQL syntax errors, working with CrowdStrike EDR/Falcon security monitoring, or building behavioral rules with the correlate() function. Handles case statements, risk categorization, multi-event correlation, investigation playbooks, and actionable security outputs.
---

# CrowdStrike LogScale Security Query Development

Expert assistance for developing security detection queries and hunting rules in CrowdStrike LogScale (formerly Humio) using CQL syntax.

## When to Use This Skill

Use this skill when you need to:
- Write or optimize LogScale/CQL security queries
- Build threat detection rules with risk categorization
- Fix CQL syntax errors (especially case statements)
- Create investigation playbooks and hunting queries
- Develop queries for AWS CloudTrail, Entra ID, or CrowdStrike EDR
- Generate actionable security outputs with user context and remediation steps
- **Build behavioral rules using `correlate()` for multi-event detection**
- **Create attack chain detections that span multiple events over time**

## Quick Start

### Basic Query Structure

```cql
// 1. Filter relevant events
#event_simpleName=<EventType>
| <field_filters>

// 2. Categorize risk
| case {
    <critical_condition> | _RiskLevel := "Critical" ;
    <high_condition> | _RiskLevel := "High" ;
    * | _RiskLevel := "Low" ;
}

// 3. Enrich with context
| match(file="entraidusers.csv", field=UserPrincipalName, include=[DisplayName])

// 4. Generate output
| table([_RiskLevel, DisplayName, <key_fields>])
```

### Critical Case Statement Rules

```cql
// ALWAYS use test() for numeric comparisons
| case {
    test(FailedLogins > 5) | _Severity := "Critical" ;  // ✅ CORRECT
    FailedLogins > 5 | _Severity := "Critical" ;        // ❌ WRONG
}

// AND/OR ARE supported in case branches (contrary to earlier docs)
// ✅ WORKS in case statements:
| case {
    DetectionTier = "RAPID" AND UniqueIPs > 1 | RiskScore := 90;
    UniqueIPs > 1 AND UniqueDevices > 1 | AttackPattern := "Distributed";
    * | RiskScore := 50;
}

// Use composite keys when AND/OR is cleaner for string matching
| _Key := format("%s-%s", field=[Type, Location])
| case {
    _Key="Admin-External" | _Risk := "High" ;
    * | _Risk := "Low" ;
}

// ALWAYS include default branch
| case {
    Status="Active" | _Label := "Active" ;
    * | _Label := "Unknown" ;  // ✅ Required
}
```

### Behavioral Rules with correlate()

For multi-event pattern detection (attack chains, behavioral sequences):

```cql
correlate(
  FailedLogin: {
    event.outcome="failure" event.action=/UserLogon/
  },
  SuccessLogin: {
    event.outcome="success" event.action=/UserLogon/
    | user.email <=> FailedLogin.user.email
  },
  sequence=true,
  within=30m,
  globalConstraints=[user.email]
)
```

**Key `correlate()` concepts:**
- **Named queries**: `FailedLogin: { ... }` - each event pattern has a name
- **Link operator `<=>`**: Correlates fields between queries
- **`sequence=true`**: Events must occur in order
- **`within=30m`**: Time window constraint
- **`globalConstraints`**: Fields all events must share

See [correlate-function.md](correlate-function.md) for complete syntax reference.

## Core Principles

**1. Actionable Over Raw**
- Include display names, risk scores, and specific actions
- Provide categorized outputs, not just event dumps
- Add business context and investigation IDs

**2. Syntax Precision**
- Use `test()` for all comparisons (>, <, >=, <=, !=)
- Use `:=` for assignments in case statements
- End each case branch with `;` semicolon
- Never nest case statements

**3. Maintainability**
- Use functions over hardcoded exclusions
- Implement dynamic classification (service account detectors)
- Keep queries focused and well-commented

**4. Risk-Based Categorization**
- Implement severity levels (Critical, High, Medium, Low)
- Assign risk scores and action priorities
- Provide specific remediation recommendations

## Common Tasks

### Fix Case Statement Errors

See [case-statements.md](case-statements.md) for:
- 12 distinct case statement patterns
- Complete syntax rules and limitations
- Common errors with before/after fixes
- Debug methodology and testing checklist

### Build Detection Query

See [query-patterns.md](query-patterns.md) for:
- Failed login monitoring and multi-tier severity scoring
- Privilege escalation detection with session correlation
- Statistical baseline anomaly detection (defineTable)
- Array operations for complex data extraction
- Geographic risk with privilege multipliers
- DNS entropy analysis for tunneling detection
- Temporal gating for duplicate alert prevention
- Data exfiltration indicators

### Troubleshoot Syntax Errors

See [troubleshooting.md](troubleshooting.md) for:
- Comprehensive error catalog
- Emergency fix templates
- When to use test() reference table
- Step-by-step debugging process

### Create Investigation Playbook

See [investigation-playbooks.md](investigation-playbooks.md) for:
- 5-phase investigation methodology
- Structured hunting approaches
- Timeline analysis techniques
- Root cause identification

### View Examples

See [examples.md](examples.md) for 11 production examples:
- Statistical anomaly detection with defineTable() baselines
- Event sequencing with selfJoinFilter()
- Aggregation with threshold detection
- Volume-based exfiltration detection
- Multi-platform pattern matching with case statements
- Named capture groups for data extraction
- Session hijacking with string formatting
- Simple aggregation with service account filtering (GitHub)
- Statistical baseline with defineTable() (AWS KMS)
- Multi-tier severity with temporal gating (EntraID brute force)
- Geographic risk with privilege multipliers (international sign-in)

## Key Syntax References

### Case Statement Structure
```cql
| case {
    condition1 | field1 := value1 | field2 := value2 ;
    test(comparison) | field := value ;
    Field=/regex/ | field := value ;
    * | field := default ;  // Always required
}
```

### When to Use test()
- Greater/less than: `test(Field > 5)`
- Not equal: `test(Field != "value")`
- Field comparison: `test(Field1 > Field2)`
- Simple equality: `Field="value"` (no test() needed)
- Regex: `Field=/pattern/` (no test() needed)

### AND/OR in Case Statements

AND/OR **works** in case branches for combining conditions:
```cql
| case {
    DetectionTier = "RAPID" AND UniqueIPs > 1 | RiskScore := 90;
    entra.privilege_category="global_admin" AND CountryRisk!="low" | CompositeRiskScore := CompositeRiskScore + 25;
    * | RiskScore := 50;
}
```

Composite keys are still useful for complex string-based matching:
```cql
| _Key := format("%s-%s-%s", field=[Protocol, Port, DestIP])
| case {
    _Key="tcp-22-0.0.0.0/0" | _Risk := "Critical" ;
    _Key=/tcp-(80|443)-.*/ | _Risk := "Low" ;
}
```

### Key Functions Quick Reference

| Function | Purpose | Example |
|----------|---------|---------|
| `test()` | Numeric comparison in case/filter | `test(count > 5)` |
| `if()` | Conditional value assignment | `if(field, then=a, else=b)` |
| `format()` | String formatting | `format("%s-%s", field=[a, b])` |
| `coalesce()` | First non-null value | `coalesce([f1, f2], as=out)` |
| `defineTable()` | Historical baseline | `defineTable(query={...}, start=7d)` |
| `match()` | CSV/table lookup | `match(file="x.csv", field=f)` |
| `selfJoinFilter()` | Multi-event correlation | `selfJoinFilter(field=[aid], where=[...])` |
| `session()` | Time-bounded grouping | `session([...], maxpause=15m)` |
| `array:contains()` | Array membership | `array:contains(array="f[]", value="v")` |
| `objectArray:eval()` | Iterate object arrays | `objectArray:eval("arr[]", ...)` |
| `shannonEntropy()` | String randomness | `shannonEntropy(DomainName)` |
| `ipLocation()` | GeoIP enrichment | `ipLocation(source.ip)` |
| `asn()` | ASN organization lookup | `asn(source.ip)` |
| `cidr()` | Subnet membership | `cidr(ip, subnet=["10.0.0.0/8"])` |
| `now()` | Current time (epoch ms) | `_current := now()` |
| `formatDuration()` | Duration display | `formatDuration(ms, from=ms, precision=2)` |

See [reference.md](reference.md) for complete syntax documentation.

### Link Operator for correlate()
```cql
// The <=> operator links fields between named queries
correlate(
  Query1: { filter1 },
  Query2: {
    filter2
    | fieldA <=> Query1.fieldB   // Links fieldA to Query1.fieldB
  },
  within=1h
)
// Output fields are prefixed: Query1.fieldB, Query2.fieldA
```

## Supporting Files

- **[correlate-function.md](correlate-function.md)** - Complete `correlate()` function reference for behavioral rules and multi-event detection
- **[case-statements.md](case-statements.md)** - Complete case statement syntax guide with 12 patterns and comprehensive error troubleshooting
- **[troubleshooting.md](troubleshooting.md)** - Error catalog, debugging methodology, emergency fixes
- **[query-patterns.md](query-patterns.md)** - Common detection patterns and reusable templates
- **[investigation-playbooks.md](investigation-playbooks.md)** - Structured hunting methodology and IR workflows
- **[examples.md](examples.md)** - Production-ready query examples for AWS, Entra ID, CrowdStrike
- **[reference.md](reference.md)** - Complete CQL syntax reference and platform integrations

## Workflow

1. **Define objective** - What threat/behavior are you detecting?
2. **Start with basic filter** - Get relevant events with simple filters
3. **Add categorization** - Implement risk-based logic with case statements
4. **Enrich context** - Add user data, geo, timeline using joins/lookups
5. **Generate output** - Create actionable format with display names and actions
6. **Validate query** - Use the CLI validator before deployment
7. **Test and refine** - Validate against historical data, adjust false positives

## Query Validation (AI-Assisted Detection Engineering)

When creating or modifying detection templates, **always validate queries before committing**:

### Validate Query CLI Command

```bash
# Validate query from a detection template
python scripts/resource_deploy.py validate-query --template <path/to/detection.yaml>

# Validate inline query
python scripts/resource_deploy.py validate-query --query '#Vendor="sase" | count()'

# Validate query from file
python scripts/resource_deploy.py validate-query --file /tmp/query.txt
```

### Output
- `VALID` (exit code 0) - Query syntax is correct
- `INVALID: <message>` (exit code 1) - Query has syntax errors

### AI Workflow for Detection Development

1. **Write the detection template** with `search.filter` query
2. **Run validation**: `python scripts/resource_deploy.py validate-query --template <path>`
3. **If INVALID**, review the query for common CQL issues:
   - Case statement syntax (missing `test()`, missing default branch `*`)
   - Incorrect use of `if()` function (use `case` statements instead)
   - AND/OR operators in case conditions (use composite keys)
   - Comparison operators without `test()` wrapper
4. **Fix and re-validate** until `VALID`
5. **Run full plan**: `python scripts/resource_deploy.py plan --resources=detection`

### Common Validation Failures

| Error Pattern | Likely Cause | Fix |
|---------------|--------------|-----|
| `NotAFunctionArgumentOperator` | Using `=` in function args like `count(x, where=field="value")` | Use case statement to create flag field, then `sum()` |
| `UnrecognizedNamedArgumentNoSuggestions` | Wrong `if()` syntax | Use `case` statement instead of `if()` |
| `ArraysNotSupportedHere` | Positional args in `if()` | Use named params: `if(condition, then=x, else=y)` |
| Generic syntax error | Case statement issues | Check for `test()`, default branch, no AND/OR |
| `Unknown error` with groupBy | Named assignment `:=` in function list | Use `as=` for count/sum/min/max, use original field name for `collect()` |
| `Unknown error` with collect | Using `as=` or `:=` with collect() | `collect()` doesn't support naming - use original field name after groupBy |

### Debugging "Unknown Error"

When you get `INVALID: Syntax error: Unknown error`, isolate the problem:

```bash
# 1. Stash changes, validate original
git stash && python scripts/resource_deploy.py validate-query --template <path>
git stash pop

# 2. Test individual syntax patterns
python scripts/resource_deploy.py validate-query --query '#Vendor="aws" | groupBy([x], function=[count()])'

# 3. Binary search - comment out half the query and validate
```

See [troubleshooting.md](troubleshooting.md) for the full debugging methodology.

## Platform Limitations

### Case Statements
- ❌ No nested case statements (use sequential case blocks instead)
- ❌ No comparisons (>, <, !=) without test() wrapper
- ❌ Cannot use field created in same case branch
- ❌ No `:=` assignment in groupBy function list
- ❌ `collect()` doesn't support `as=` parameter - use original field name
- ✅ AND/OR conditions work in case branches (e.g., `field1="a" AND field2 > 5`)
- ✅ Use sequential case statements for complex multi-step logic
- ✅ Wrap numeric comparisons in test()
- ✅ Create fields first, use in next case statement
- ✅ Always include default branch (`*`)
- ✅ Use `as=` for count/sum/min/max in groupBy

### correlate() Function
- ❌ Cannot use after aggregators (groupBy, count, etc.)
- ❌ Cannot appear inside function parameters
- ❌ Cannot use aggregate functions within queries
- ❌ Only `<=>` operator for linking (no other comparisons)
- ❌ Results must fit within memory quota
- ✅ Supports 3+ queries (unlike join which only supports 2)
- ✅ Use `globalConstraints` to simplify links
- ✅ Use `sequence=true` only when event order matters

## Requirements

This skill works with:
- CrowdStrike LogScale / Humio
- CQL (CrowdStrike Query Language)
- CSV lookup files (entraidusers.csv, entraidgroups.csv)
- Custom functions (aws_service_account_detector, etc.)

## Need Help?

- **Syntax error?** → Check [troubleshooting.md](troubleshooting.md)
- **Case statement failing?** → See [case-statements.md](case-statements.md)
- **Need a pattern?** → Browse [query-patterns.md](query-patterns.md)
- **Building detection?** → See [examples.md](examples.md)
- **Investigation workflow?** → See [investigation-playbooks.md](investigation-playbooks.md)
- **Behavioral rules / correlate()?** → See [correlate-function.md](correlate-function.md)
