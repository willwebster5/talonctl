---
name: behavioral-detections
description: Design multi-event behavioral detection rules using CrowdStrike NG-SIEM correlate() function. Use when building attack chain detections, correlating multiple events across time windows, or creating behavioral rules that detect complex threat patterns across AWS, EntraID, and CrowdStrike data sources.
allowed-tools: Read, Grep, Glob, Bash
---

# Behavioral Detection Engineering

Design and implement behavioral detection rules that identify attack patterns across multiple events using CrowdStrike NG-SIEM's `correlate()` function.

## When to Use This Skill

Use this skill when you need to:
- Design **attack chain detections** (recon → escalation → persistence)
- Build **behavioral rules** that span multiple events over time
- Create **compound detections** from multiple rule triggers
- Correlate events across **different data sources** (AWS + EntraID + CrowdStrike)
- Detect **multi-stage attacks** that single-event rules would miss

## Quick Start: Your First Behavioral Rule

```cql
// Detect failed logins followed by successful access
correlate(
  FailedLogins: {
    event.outcome="failure"
    event.action=/UserLogon|Sign-in/
  },
  SuccessfulLogin: {
    event.outcome="success"
    event.action=/UserLogon|Sign-in/
    | user.email <=> FailedLogins.user.email
  },
  sequence=true,
  within=30m,
  globalConstraints=[user.email]
)
| table([SuccessfulLogin.user.email, FailedLogins.source.ip])
```

## Core Concepts

### Behavioral vs Correlation Rules

| Type | Function | Use Case |
|------|----------|----------|
| **Correlation Rule** | Single-event threshold | "Alert on 50+ failed logins" |
| **Behavioral Rule** | Multi-event pattern via `correlate()` | "Alert on failed logins FOLLOWED BY success" |

### correlate() Key Components

1. **Named Queries**: Each event pattern has a unique name
   ```cql
   QueryName: { filter_expression }
   ```

2. **Link Operator `<=>`**: Correlates fields between queries
   ```cql
   | user.email <=> OtherQuery.user.email
   ```

3. **Sequence**: Enforce chronological order
   ```cql
   sequence=true  // Events must occur in order
   ```

4. **Time Window**: Constrain event timing
   ```cql
   within=1h  // All events within 1 hour
   ```

5. **Global Constraints**: Fields all events must share
   ```cql
   globalConstraints=[user.email, cloud.account.id]
   ```

## Attack Pattern Design Workflow

### Step 1: Define the Attack Chain

Identify the stages of the attack you want to detect:

| Stage | Event Type | Example |
|-------|------------|---------|
| Reconnaissance | Read/List operations | `DescribeInstances`, `ListBuckets` |
| Initial Access | Authentication events | `UserLogon`, `ConsoleLogin` |
| Privilege Escalation | Permission changes | `AttachUserPolicy`, `AddMemberToRole` |
| Persistence | Credential creation | `CreateAccessKey`, `CreateLoginProfile` |
| Exfiltration | Data access | `GetObject`, `FileDownloaded` |

### Step 2: Map to correlate() Queries

```cql
correlate(
  // Stage 1: Reconnaissance
  Recon: {
    event.action=~in(values=["DescribeInstances", "ListBuckets"])
  },

  // Stage 2: Privilege Escalation
  PrivEsc: {
    event.action="AttachUserPolicy"
    | Vendor.userIdentity.arn <=> Recon.Vendor.userIdentity.arn
  },

  // Stage 3: Persistence
  Persist: {
    event.action="CreateAccessKey"
    | Vendor.userIdentity.arn <=> Recon.Vendor.userIdentity.arn
  },

  sequence=true,
  within=2h,
  globalConstraints=[Vendor.userIdentity.arn]
)
```

### Step 3: Add Context and Output

```cql
| ipLocation(Recon.source.ip)
| case {
    Recon.source.ip.country!="United States" | _Risk := "Critical" ;
    * | _Risk := "High" ;
}
| table([_Risk, Recon.Vendor.userIdentity.arn, Recon.source.ip, Recon.source.ip.country])
```

## Supporting Files

- **[attack-patterns.md](attack-patterns.md)** - MITRE ATT&CK-aligned attack chain patterns
- **[aws-behavioral-rules.md](aws-behavioral-rules.md)** - AWS-specific behavioral detection examples
- **[entraid-behavioral-rules.md](entraid-behavioral-rules.md)** - EntraID authentication pattern examples
- **[detection-chaining.md](detection-chaining.md)** - How to correlate rule triggers (RTEs)

## Detection Output Types

| Outcome | Field Value | Description |
|---------|-------------|-------------|
| Behavioral Detection | `Ngsiem.event.outcome="behavioral-detection"` | Multi-event correlate() rule |
| Correlation Detection | `Ngsiem.event.outcome="correlation-rule-detection"` | Single-event threshold rule |
| Behavioral Case | `Ngsiem.event.outcome="behavioral-case"` | Creates investigation case |

## Best Practices

### 1. Start Simple, Add Complexity

```cql
// Start with 2 events
correlate(
  EventA: { ... },
  EventB: { ... | field <=> EventA.field },
  within=1h
)

// Then add more stages after validation
```

### 2. Choose Appropriate Time Windows

| Attack Pattern | Recommended `within` |
|----------------|---------------------|
| Authentication brute force | 15-30m |
| Privilege escalation chain | 1-2h |
| Data staging → exfil | 4-24h |
| Insider threat patterns | 24-72h |

### 3. Use globalConstraints for Shared Fields

```cql
// Cleaner than repeating links
globalConstraints=[user.email, cloud.account.id]
```

### 4. Sequence Only When Order Matters

```cql
// Attack chain - order matters
sequence=true

// Alert correlation - either can come first
sequence=false
```

### 5. Validate Lookback > Within

```yaml
search:
  filter: |
    correlate(... within=2h ...)
  lookback: 4h  # Must exceed 'within' value
```

### 6. Validate Component Query Volume Before Wiring

Before assembling a `correlate()` rule, run each component query independently against 30d of data. A noisy component query produces a noisy behavioral rule — and behavioral rules are harder to tune after the fact because the correlate() wrapper obscures which leg is generating volume.

```
// Run each leg standalone first:
ngsiem_query: <component_filter_A> | groupBy([actor, key_field], function=count()) | sort(count, desc)
ngsiem_query: <component_filter_B> | groupBy([actor, key_field], function=count()) | sort(count, desc)
```

If any component returns unexpectedly high volume, tune it individually before combining. The target is that each leg fires only on genuinely anomalous events — a behavioral rule combining two noisy legs produces noisy² alerts.

## Common Patterns

### Pattern: Authentication Abuse
Failed attempts → Successful login
See [entraid-behavioral-rules.md](entraid-behavioral-rules.md)

### Pattern: Privilege Escalation Chain
Create user → Attach admin policy → Create credentials
See [aws-behavioral-rules.md](aws-behavioral-rules.md)

### Pattern: Detection Correlation
Combine multiple rule triggers into compound alert
See [detection-chaining.md](detection-chaining.md)

### Pattern: Cross-Source Correlation
Endpoint activity → Cloud API calls
See [attack-patterns.md](attack-patterns.md)

## Syntax Reference

For complete `correlate()` syntax documentation, see:
- [correlate-function.md](../logscale-security-queries/correlate-function.md) in the logscale-security-queries skill

## Need Help?

- **Designing attack chains?** → See [attack-patterns.md](attack-patterns.md)
- **AWS-specific patterns?** → See [aws-behavioral-rules.md](aws-behavioral-rules.md)
- **EntraID patterns?** → See [entraid-behavioral-rules.md](entraid-behavioral-rules.md)
- **Chaining detections?** → See [detection-chaining.md](detection-chaining.md)
- **CQL syntax issues?** → See [correlate-function.md](../logscale-security-queries/correlate-function.md)