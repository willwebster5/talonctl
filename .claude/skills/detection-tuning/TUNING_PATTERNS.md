# Common Detection Tuning Patterns

This document provides reusable CQL patterns for tuning CrowdStrike NGSIEM detections based on the environment context and available enrichment functions.

---

## Pattern 1: Service Account Exclusion

**Problem**: Automated activities generate false positives in user behavior detections.

**Solution**: Filter out known service accounts before alerting.

### AWS CloudTrail

```cql
// Basic service account filtering
| $aws_enrich_user_identity()
| $aws_classify_identity_type(include_service_detection="true")
| aws.is_human_identity=true

// Strict mode - excludes more patterns
| $aws_service_account_detector(strict_mode="true")
| aws.is_service_account=false

// With confidence filtering
| $aws_service_account_detector()
| NOT (aws.is_service_account=true AND aws.svc_detection_confidence=~in(values=["high", "medium"]))
```

**Detected Service Account Types** (8 categories):
- **monitoring**: monitoring vendor, observability tools
- **cicd**: GitHub Actions, CodeBuild, Jenkins
- **iac**: Terraform, CloudFormation automation
- **aws-managed**: AWS native service roles (SSO, ControlTower, SecurityHub)
- **etl-pipeline**: ETL tools, data ingestion tools
- **container-task**: ECS Fargate, task roles
- **serverless**: Lambda roles
- **vendor-app/data-platform**: Third-party service integrations

### GitHub Service Accounts

```cql
// Per-detection filtering (RECOMMENDED)
| $github_service_account_detector()
| github.service_account_type!="merge-queue"
| github.service_account_type!="dependabot"

// Exclude multiple types
| $github_service_account_detector()
| github.service_account_type!="merge-queue"
| github.service_account_type!="github-actions"

// All-or-nothing filtering
| $github_apply_exclusions()
| github.is_excluded=false
```

**GitHub Service Account Types**:
| Type | Description | Confidence |
|------|-------------|------------|
| `merge-queue` | GitHub merge queue bot | high |
| `dependabot` | Dependency update automation | high |
| `github-actions` | GitHub Actions bot | high |
| `github-bot` | Other `[bot]` suffixed accounts | medium |
| `human-user` | Not detected as service account | none |

### Known Service Account Patterns

```cql
// Direct pattern exclusion (when functions aren't applicable)
| UserIdentifier!~/monitoring-integration|crowdstrike|terraform|etl-tool/i
| ActualUserName!~/github-actions-role|dev-environment-server|lambda-role/i
```

### EntraID Service Accounts

```cql
| $entraid_enrich_user_identity()
| entra.user_type!="service_account"
| entra.user_type!="application_account"
```

---

## Pattern 2: Trusted Network Filtering

**Problem**: Corporate VPN (SASE) traffic triggers external access alerts.

**Solution**: Exclude known trusted network sources.

### Basic SASE Filtering

```cql
| $trusted_network_detector()
| net.is_excluded=false
```

### Extended Trust (AWS + GitHub + Private)

```cql
| $trusted_network_detector(extend_trust="true", include_private="true")
| net.is_excluded=false
| net.risk="review"  // Only traffic needing review
```

### Direct ASN-Based Filtering

```cql
// When you need direct control
| asn(source.ip)
| source.ip.org!~/Cloud SASE/i

// Multiple trusted ASNs
| asn(source.ip)
| NOT in(field="source.ip.org", values=["Cloud SASE", "amazon.com"])
```

### SASE Connection Validation

```cql
| $sase_validate_connection_source()
| sase.connection_type="external-direct"  // Only truly external
| sase.connection_risk="high"
```

---

## Pattern 3: Identity Enrichment Pipeline

**Problem**: Raw events lack context for actionable alerting.

**Solution**: Chain enrichment functions for comprehensive identity context.

### AWS Full Pipeline

```cql
#repo=cloudtrail
| $aws_enrich_user_identity()
| $aws_classify_identity_type(include_service_detection="true")
| $trusted_network_detector(extend_trust="true")
| $score_geo_risk()

// Filter criteria
| aws.is_human_identity=true
| net.is_excluded=false
| geo.final_should_alert=true

// Alert with context
| select([
    @timestamp,
    aws.user_identity,
    aws.identity_category,
    aws.identity_risk_level,
    net.provider,
    geo.risk_category,
    Country,
    event.action
])
```

### EntraID Full Pipeline

```cql
#repo=microsoft_graphapi
| $entraid_enrich_user_identity()
| $entraid_classify_user_type()
| $entraid_lookup_trust_level()
| $entraid_add_authorization_context()
| $entraid_flag_unauthorized_actions()

// Filter
| entra.user_type="user_account"
| entra.should_alert=true
```

### Universal Identity Enrichment (Cross-Platform)

```cql
// AWS events with universal enrichment
#repo=cloudtrail
| $aws_enrich_user_identity()
| UserEmail := lower(aws.user_identity)
| $identity_enrich_from_email()
| id.is_admin="True"
| id.has_prod_access="True"

// EntraID events with universal enrichment
#Vendor="microsoft" #event.dataset=/entraid/
| $entraid_enrich_user_identity()
| $identity_enrich_from_email()
| id.department="Engineering"

// SASE events (already includes full enrichment)
#Vendor="sase"
| $sase_enrich_user_identity()
| sase.is_admin=true
| sase.department=*
```

**Universal Enrichment Output Fields**:
- **Organizational**: id.department, id.job_title, id.manager_name, id.office_location
- **Security Flags**: id.is_admin, id.is_contractor, id.is_engineer, id.has_prod_access, id.has_github_access
- **Trust & Risk**: id.trust_level, id.risk_score, id.privilege_tier
- **Cross-Platform**: id.aws_username, id.github_username, id.admin_account

### GitHub Identity Pipeline

```cql
source_type=github
| $github_enrich_event_context()
| $github_classify_sender_type()
| $github_service_account_detector()
| github.is_human_actor=true
| github.service_account_type="human-user"
```

---

## Pattern 4: Threshold Tuning

**Problem**: Default thresholds don't match environment size (~500 users).

**Solution**: Adjust thresholds based on expected activity volume.

### Brute Force Thresholds

```cql
// Original OOTB threshold (too low for 500 users)
// | failed_attempts >= 5

// Tuned threshold - reduces false positives
| groupBy([user.email, source.ip],
    function=[
        failed_attempts := count(),
        unique_accounts := count(field=user.email, distinct=true),
        first_seen := min(@timestamp),
        last_seen := max(@timestamp)
    ])

// Use OR logic for flexibility
| failed_attempts >= 50 OR unique_accounts >= 10
```

### Data Exfiltration Thresholds

```cql
// Calculate data volume
| _totalBytes := sum(response.bytes)
| _totalGigaBytes := _totalBytes / 1000000000

// High threshold for data transfer
| _totalGigaBytes > 100

// Or relative to baseline
| $create_baseline_60d()
| match(file="baseline_stats", field=EntityId)
| test(_totalGigaBytes > BaselineAvg * 10)
```

### Activity Count Thresholds

```cql
// Environment-appropriate counts for ~500 users
| case {
    // Admin activity
    RoleName=~/Admin/ | activity_threshold := 50;
    // Regular user activity
    * | activity_threshold := 100;
}
| test(event_count > activity_threshold)
```

---

## Pattern 5: Time-Based Filtering

**Problem**: After-hours activity from US timezones flagged incorrectly.

**Solution**: Account for all US timezones in business hours calculations.

### US Business Hours (All Timezones)

```cql
// Extract hour in UTC
| hour := formatTime("%H", field=@timestamp, timezone="UTC")

// US business hours: 9 AM ET to 9 PM PT = 13:00 to 05:00 UTC
| case {
    // Normal business hours (covers all US timezones)
    test(hour >= 13) OR test(hour < 5) | IsBusinessHours := true;
    * | IsBusinessHours := false;
}

// Alert only on off-hours for sensitive actions
| IsBusinessHours=false
```

### Weekend Detection

```cql
| dayOfWeek := formatTime("%u", field=@timestamp)  // 1=Monday, 7=Sunday
| case {
    test(dayOfWeek >= 6) | IsWeekend := true;
    * | IsWeekend := false;
}

// Weekend activity for sensitive accounts
| IsWeekend=true
| aws.identity_category=~in(values=["root_account", "admin_role"])
```

---

## Pattern 6: Geographic Risk Assessment

**Problem**: All non-US access flagged despite legitimate remote work.

**Solution**: Use geographic risk scoring with VPN context.

### Basic Geo Filtering (US-Only Workforce)

```cql
| ipLocation(source.ip)
| NOT in(field="source.ip.country", values=["United States", "Canada", "Mexico"])
```

### Full Geo Risk Pipeline

```cql
// Optional: Add VPN context first
| $sase_validate_connection_source()

// Score geographic risk
| $score_geo_risk()

// Filter based on risk
| case {
    // Always alert on high-risk countries
    geo.is_high_risk_country=true | alert := true;
    // Alert on high adjusted risk
    test(geo.adjusted_risk_score >= 70) | alert := true;
    // Alert if not on VPN and risky
    sase.connection_type="external-direct" AND test(geo.risk_score >= 50) | alert := true;
    * | alert := false;
}
| alert=true
```

### International Travel Handling

```cql
// Check EntraID travel exception group
| match(file="entraid-users.csv", field=UserEmail, column=email, include=[groups])
| case {
    groups=~/International Travel/ | HasTravelException := true;
    * | HasTravelException := false;
}

// Don't alert on approved travelers
| NOT (HasTravelException=true AND geo.is_authorized_country=false)
```

---

## Pattern 7: Cross-Account Trust Validation

**Problem**: Legitimate cross-account access triggers unauthorized alerts.

**Solution**: Validate trust relationships before alerting.

### Cross-Account Detection

```cql
#repo=cloudtrail eventName=AssumeRole
| $aws_enrich_user_identity()
| $aws_validate_cross_account_trust()

// Only alert on untrusted or suspicious patterns
| aws.cross_account_risk=~in(values=["critical", "high"])
| aws.is_suspicious_pattern=true

// Include context for investigation
| select([
    @timestamp,
    aws.user_identity,
    aws.source_account,
    aws.target_account,
    aws.cross_account_trust_type,
    aws.cross_account_role_name,
    aws.cross_account_operation_type
])
```

### Trust Relationship Summary

```cql
| $aws_validate_cross_account_trust()

// Group by trust type for baseline
| groupBy([aws.cross_account_trust_type, aws.cross_account_risk], function=count())
```

---

## Pattern 8: Baseline Anomaly Detection

> **Moved to catalog:** See `.claude/skills/cql-patterns/patterns/baselining.md` — "Time-window baseline comparison" pattern.

---

## Pattern 9: Multi-Condition Alert Logic

**Problem**: Single conditions are too restrictive or too permissive.

**Solution**: Use OR logic for flexible alerting.

### Combined Threshold Logic

```cql
| groupBy([user.email, source.ip],
    function=[
        failed_count := count(),
        unique_targets := count(field=target, distinct=true),
        duration_mins := (max(@timestamp) - min(@timestamp)) / 60000
    ])

// Alert on ANY of these conditions
| (failed_count >= 50)  // High volume
    OR (unique_targets >= 10)  // Account spray
    OR (failed_count >= 20 AND duration_mins < 5)  // Rapid burst
```

### Risk-Based Escalation

```cql
| $aws_classify_identity_type(include_service_detection="true")
| $score_geo_risk()

// Calculate combined risk
| case {
    // Critical: Root + external
    aws.identity_category="root_account" AND sase.connection_type="external-direct"
        | AlertSeverity := 90 | AlertReason := "Root account external access";

    // High: Admin from high-risk country
    aws.identity_category="admin_role" AND geo.is_high_risk_country=true
        | AlertSeverity := 70 | AlertReason := "Admin from high-risk country";

    // Medium: Human user anomaly
    aws.is_human_identity=true AND test(geo.risk_score >= 70)
        | AlertSeverity := 50 | AlertReason := "User geo anomaly";

    * | AlertSeverity := 0;
}
| AlertSeverity > 0
```

---

## Pattern 10: Field Coalescing

**Problem**: Different event types have identity in different fields.

**Solution**: Coalesce fields for consistent processing.

### Multi-Source Field Extraction

```cql
// Coalesce user identity from multiple sources
| coalesce([
    Vendor.userIdentity.arn,
    Vendor.userIdentity.userName,
    user.email,
    user.name
], as="UserIdentity")

// Coalesce IP address
| coalesce([
    source.ip,
    Vendor.sourceIPAddress,
    client_ip,
    RemoteAddressIP4
], as="SourceIP")

// Coalesce event action
| coalesce([
    event.action,
    Vendor.eventName,
    eventName,
    action
], as="EventAction")
```

---

## Pattern 11: Behavioral Rule Tuning (correlate())

**Problem**: Behavioral rules using `correlate()` require different tuning approaches than single-event rules.

**Solution**: Optimize time windows, sequence settings, and correlation keys.

### Time Window Optimization

```cql
// Too narrow - may miss legitimate attack chains
correlate(
  Step1: { ... },
  Step2: { ... | field <=> Step1.field },
  within=5m  // Too short for multi-stage attacks
)

// Better - balanced for attack patterns
correlate(
  Step1: { ... },
  Step2: { ... | field <=> Step1.field },
  within=1h  // Reasonable for most attack chains
)
```

**Time Window Guidelines:**
| Attack Type | Recommended `within` |
|-------------|---------------------|
| Brute force → success | 15-30m |
| Privilege escalation chain | 1-2h |
| Data staging → exfil | 4-24h |
| Multi-day campaign | Use multiple rules |

### Sequence vs Non-Sequence

```cql
// Use sequence=true when order matters (attack chains)
correlate(
  Recon: { event.action=/Describe|List/ },
  Escalate: { event.action=/Create.*User|Attach.*Policy/ | ... },
  Persist: { event.action=/CreateAccessKey/ | ... },
  sequence=true,  // Must happen in order
  within=2h
)

// Use sequence=false when order doesn't matter
correlate(
  AlertA: { rule.name=/BruteForce/ },
  AlertB: { rule.name=/DataExfil/ | user <=> AlertA.user },
  sequence=false,  // Either can come first
  within=4h
)
```

### Using globalConstraints Effectively

```cql
// Without globalConstraints (verbose, error-prone)
correlate(
  EventA: { filter1 },
  EventB: { filter2 | user.email <=> EventA.user.email },
  EventC: { filter3 | user.email <=> EventA.user.email },
  EventD: { filter4 | user.email <=> EventA.user.email },
  within=1h
)

// With globalConstraints (cleaner, more maintainable)
correlate(
  EventA: { filter1 },
  EventB: { filter2 },
  EventC: { filter3 },
  EventD: { filter4 },
  within=1h,
  globalConstraints=[user.email]  // All events must share user.email
)
```

### Enrichment Inside vs Outside correlate()

```cql
// ❌ WRONG - Enrichment inside correlate queries (limited support)
correlate(
  EventA: {
    event.action="CreateUser"
    | $aws_enrich_user_identity()  // May not work
  },
  ...
)

// ✅ CORRECT - Enrichment after correlate output
correlate(
  EventA: { event.action="CreateUser" },
  EventB: { event.action="AttachPolicy" | ... },
  ...
)
| ipLocation(EventA.source.ip)
| asn(EventA.source.ip)
```

### Behavioral Rule YAML Template

```yaml
name: "Behavioral - Multi-Stage Attack Detection"
resource_id: behavioral_multi_stage_attack
description: |
  Detects multi-stage attack patterns using correlate() function.

  Attack Pattern Detected:
  1. Initial reconnaissance activity
  2. Privilege escalation action
  3. Persistence mechanism creation

  Tuning Applied:
  - sequence=true for attack chain ordering
  - within=2h covers expected attack duration
  - globalConstraints on user ARN for correlation

severity: 70
status: active
tactic: TA0004  # Privilege Escalation
technique: T1098  # Account Manipulation
search:
  filter: |
    correlate(
      Recon: {
        #Vendor="aws"
        event.action=~in(values=["DescribeInstances", "ListBuckets", "GetAccountAuthorizationDetails"])
        | $aws_enrich_user_identity()
        | aws.is_human_identity=true
      } include: [source.ip, aws.identity_category],
      PrivEsc: {
        #Vendor="aws"
        event.action=~in(values=["CreateUser", "AttachUserPolicy", "PutRolePolicy"])
        | Vendor.userIdentity.arn <=> Recon.Vendor.userIdentity.arn
      } include: [Vendor.requestParameters.userName, Vendor.requestParameters.policyArn],
      Persist: {
        #Vendor="aws"
        event.action=~in(values=["CreateAccessKey", "CreateLoginProfile"])
        | Vendor.userIdentity.arn <=> Recon.Vendor.userIdentity.arn
      } include: [Vendor.requestParameters.userName],
      sequence=true,
      within=2h,
      globalConstraints=[Vendor.userIdentity.arn]
    )
    | ipLocation(Recon.source.ip)
    | case {
        Recon.source.ip.country!="United States" | _GeoRisk := "High" ;
        * | _GeoRisk := "Normal" ;
    }
  lookback: 4h
  trigger_mode: summary
  outcome: detection
operation:
  schedule:
    definition: '@every 1h'
```

---

## Pattern 12: GitHub Service Account Filtering

**Problem**: GitHub bot activity (merge queue, dependabot, Actions) triggers false positives in repository detections.

**Solution**: Use `$github_service_account_detector()` for per-detection filtering instead of all-or-nothing exclusions.

### Basic Filtering (Exclude Merge Queue)

```cql
source_type=github
| Vendor.deleted="true"
| Vendor.sender.login=*

// Filter service accounts - exclude merge queue bot
| $github_service_account_detector()
| github.service_account_type!="merge-queue"

// Aggregate by user
| groupBy([Vendor.sender.login, Vendor.organization.login], function=count(as=DeletionCount))
| test(DeletionCount >= 3)
```

### Exclude Multiple Service Account Types

```cql
source_type=github
| event.action="repo.branch_protection_rule.deleted"

// Exclude merge queue AND dependabot
| $github_service_account_detector()
| github.service_account_type!="merge-queue"
| github.service_account_type!="dependabot"
| github.service_account_type!="github-actions"

// Only alert on human actors
| github.is_service_account=false
```

### Comparison: Per-Detection vs All-or-Nothing

```cql
// ❌ All-or-Nothing Filtering (inflexible)
// Excludes ALL bots from ALL detections
| $github_apply_exclusions()
| github.is_excluded=false

// ✅ Per-Detection Filtering (flexible)
// Each detection chooses which bots to exclude
| $github_service_account_detector()
| github.service_account_type!="merge-queue"  // This detection allows dependabot
```

**Why Per-Detection Filtering?**
- **Merge queue deletions**: Often benign, exclude from branch deletion alerts
- **Dependabot PRs**: May want to detect unusual dependabot behavior separately
- **GitHub Actions**: Sometimes legitimate, sometimes suspicious depending on detection
- **Flexibility**: Different detections have different noise profiles

### GitHub Service Account Types Reference

| github.service_account_type | Example Actor | Common Activities | Detection Confidence |
|-------------------|---------------|-------------------|---------------------|
| `merge-queue` | `github-merge-queue[bot]` | Branch creation/deletion, merges to protected branches | high |
| `dependabot` | `dependabot[bot]` | Dependency PR creation, branch updates | high |
| `github-actions` | `github-actions[bot]` | Workflow automation, releases | high |
| `github-bot` | `renovate[bot]`, custom `[bot]` | Various automation (catch-all for `[bot]` suffix) | medium |
| `human-user` | Regular GitHub users | All human-initiated actions | none |

### Detection-Specific Filtering Recommendations

| Detection Type | Recommended Filter |
|---------------|-------------------|
| Branch deletions | Exclude `merge-queue` only |
| Branch protection changes | Exclude none (alert on all changes) |
| Repository deletion | Exclude none (critical action) |
| Force push detection | Exclude `merge-queue`, `github-actions` |
| Secret scanning bypass | Exclude none (security-critical) |

---

## Pattern 13: Statistical Baseline Detection

> **Moved to catalog:** See `.claude/skills/cql-patterns/patterns/baselining.md` — "Time-window baseline comparison" and "$createBaseline functions" patterns.

---

## Pattern 14: Multi-Tier Severity Scoring

> **Moved to catalog:** See `.claude/skills/cql-patterns/patterns/scoring.md` — "Severity tiering with temporal gating" pattern.

---

## Pattern 15: Privilege-Based Risk Multipliers

> **Moved to catalog:** See `.claude/skills/cql-patterns/patterns/scoring.md` — "Weighted case{} scoring" pattern.

---

## Pattern 16: Temporal Correlation Within Windows

**Problem**: Single-event detections miss attack chains where multiple related events happen in sequence.

**Solution**: Use `bucket(span=Xm)` to correlate events within time windows without full `correlate()` complexity.

### TAP Creation + Security Info Deletion Within Window

```cql
#Vendor="microsoft" #event.dataset="entraid.audit" #repo!="xdr*"
| Vendor.properties.initiatedBy.app.appId=*

// Classify events into categories
| case {
    event.action="user-registered-security-info"
    | event.reason="User registered temporary access pass method"
    | objectArray:eval(
        array="Vendor.properties.targetResources[]",
        asArray="modProps[]",
        var=y,
        function={
            objectArray:eval(
                array="y.modifiedProperties[]",
                asArray="out[]",
                var=x,
                function={
                    x.displayName=/AccessPassUsage/i x.newValue=/Multiple/i
                    | out := "true"
                }
            )
            | out[0]=*
            | modProps := "true"
        }
    )
    | modProps[0]=*
    | _tap_create := "true"
    | formatTime("%Y-%m-%d %H:%M:%S.%Z", field=@timestamp, as=_tap_added_time);

    event.action="user-deleted-security-info"
    | event.reason!=/temporary access pass method/i
    | _delete := "true"
    | formatTime("%Y-%m-%d %H:%M:%S.%Z", field=@timestamp, as=_delete_security_info_time);
}

// Correlate within 10-minute time windows
| bucket(
    function=[
        groupBy(
            [
                Vendor.properties.targetResources[0].userPrincipalName,
                Vendor.properties.targetResources[0].id,
                Vendor.properties.initiatedBy.app.appId
            ],
            function=[
                collect(
                    _delete,
                    _tap_create,
                    event.reason,
                    _delete_security_info_time,
                    _tap_added_time
                )
            ]
        )
    ],
    span=10m  // 10-minute correlation window
)

| formatTime("%Y-%m-%d %H:%M:%S.%Z", field=_bucket, as=time_bucket)

// Only alert when BOTH events occurred in the window
| _delete=* _tap_create=*

| drop([_delete, _tap_create, _bucket])
```

### Temporal Correlation Pattern Breakdown

**When to Use `bucket(span=Xm)`:**
- Need to detect multiple related events within a time window
- Events must happen "close together" but order doesn't matter (or use sequence logic inside bucket)
- Simpler than full `correlate()` for 2-3 event types
- Want to group by time + entity (user, host, IP)

**Time Window Selection:**

| Attack Pattern | Recommended `span` | Reasoning |
|---------------|-------------------|-----------|
| Account takeover steps | 5-15m | Attacker moves quickly after initial access |
| Privilege escalation chain | 10-30m | Multiple API calls to achieve escalation |
| Data staging → exfil | 1-4h | May download, compress, then upload |
| Reconnaissance → exploit | 30m-2h | Time to identify targets and execute |

### Bucket + GroupBy Pattern

```cql
// Pattern: Detect user performing multiple suspicious actions within time window

| bucket(
    function=[
        groupBy(
            [user.email, source.ip],  // Group by entity
            function=[
                count(event.action, as=ActionCount),  // Count actions in window
                collect([event.action]),  // List of actions
                count(event.action, as=UniqueActions, distinct=true)  // Distinct actions
            ]
        )
    ],
    span=15m  // 15-minute windows
)

// Filter to windows with multiple suspicious actions
| UniqueActions >= 3
```

### Complex Object Traversal for Event Classification

```cql
// Traverse nested arrays to check for specific conditions
| objectArray:eval(
    array="Vendor.properties.targetResources[]",  // Array to iterate
    asArray="modProps[]",  // Output array name
    var=y,  // Variable for current element
    function={
        objectArray:eval(
            array="y.modifiedProperties[]",  // Nested array
            asArray="out[]",
            var=x,
            function={
                // Check conditions on nested elements
                x.displayName=/AccessPassUsage/i x.newValue=/Multiple/i
                | out := "true"  // Set flag if condition met
            }
        )
        | out[0]=*  // Check if any nested element matched
        | modProps := "true"  // Set outer flag
    }
)

// Verify the flag was set
| modProps[0]=*
| _event_type := "tap_multi_use_created"
```

**When to Use `objectArray:eval`:**
- Event data contains arrays of objects (common in EntraID audit logs)
- Need to check if ANY element in array matches a condition
- Need to extract specific values from nested structures
- Alternative to complex regex or multiple field checks

### Multi-Event Detection Within Windows

```cql
// Detect credential access + data access within 30 minutes

| case {
    event.action=~in(values=["CreateAccessKey", "GetSecretValue", "GenerateDataKey"])
        | _cred_access := "true";
    event.action=~in(values=["GetObject", "DownloadFile", "ListBuckets"])
        | _data_access := "true";
}

| bucket(
    function=[
        groupBy(
            [Vendor.userIdentity.arn, source.ip],
            function=[
                collect([_cred_access, _data_access, event.action, @timestamp])
            ]
        )
    ],
    span=30m
)

// Alert when both credential access AND data access occurred in same window
| _cred_access=* _data_access=*

// Enrich after correlation
| ipLocation(source.ip)
```

### Bucket vs Correlate Decision Matrix

| Factor | Use `bucket(span=Xm)` | Use `correlate()` |
|--------|----------------------|-------------------|
| Number of event types | 2-3 | 3+ |
| Event order matters | No (or handle with logic) | Yes (with `sequence=true`) |
| Complexity | Simple correlation | Multi-stage attack chains |
| Window size | < 1 hour | Minutes to hours |
| Enrichment needs | After bucket | After correlate |
| Maintenance | Easier | More complex |

---

## Pattern 17: Universal Identity Enrichment Pipeline

**Problem**: Cross-platform detections need consistent identity context (privilege, department, manager) regardless of data source.

**Solution**: Two-tier enrichment pattern - vendor-specific extraction → universal enrichment.

### Two-Tier Enrichment Pattern

**Tier 1: Vendor-Specific Identity Extraction**

```cql
// AWS CloudTrail → Extract UserIdentity
#repo=cloudtrail
| $aws_enrich_user_identity()
| UserEmail := lower(UserIdentity)  // Normalize to UserEmail for Tier 2

// EntraID → Extract UserEmail directly
#Vendor="microsoft" #event.dataset=/entraid/
| $entraid_enrich_user_identity()
// UserEmail already set by function

// GitHub → Extract from sender field
source_type=github
| UserEmail := lower(Vendor.sender.login)
// Note: GitHub usernames may not be email addresses

// SASE → Use full enrichment function (includes Tier 2)
#Vendor="sase"
| $sase_enrich_user_identity()
// Already includes full EntraID enrichment - skip Tier 2
```

**Tier 2: Universal Enrichment via `$identity_enrich_from_email()`**

```cql
// After Tier 1 sets UserEmail, call universal enrichment
| $identity_enrich_from_email()

// Now have access to:
//   - Organizational: Department, JobTitle, ManagerName, OfficeLocation
//   - Security Flags: IsAdmin, IsContractor, HasProdAccess, HasGitHubAccess
//   - Trust & Risk: TrustLevel, RiskScore, PrivilegeTier
//   - Cross-Platform: AWSUsername, GitHubUsername, AdminAccount
```

### Complete AWS CloudTrail + Universal Enrichment

```cql
#repo=cloudtrail
| event.action="AssumeRole"

// Tier 1: AWS-specific identity extraction
| $aws_enrich_user_identity()
| $aws_classify_identity_type(include_service_detection="true")

// Filter to human identities only
| IsHumanIdentity=true

// Tier 2: Universal identity enrichment
| UserEmail := lower(UserIdentity)
| $identity_enrich_from_email()

// Now filter using universal fields
| IsAdmin="True"
| HasProdAccess="True"
| Department=*

// Alert with enriched context
| select([
    @timestamp,
    UserEmail,
    UserDisplayName,
    Department,
    JobTitle,
    IsAdmin,
    HasProdAccess,
    PrivilegeTier,
    event.action,
    Vendor.requestParameters.roleArn
])
```

### EntraID + Universal Enrichment for Cross-Platform Context

```cql
#Vendor="microsoft" #event.dataset=/entraid\.signin/
| #event.outcome=success

// Tier 1: EntraID-specific extraction
| $entraid_enrich_user_identity()
// Sets: UserEmail, UserType, IsMFACompliant, etc.

// Tier 2: Universal enrichment adds cross-platform context
| $identity_enrich_from_email()

// Now can check if EntraID user has AWS access
| AWSUsername=*  // User has AWS IAM account

// Filter to users with both EntraID + AWS access
| select([
    @timestamp,
    UserEmail,
    UserDisplayName,
    Department,
    AWSUsername,  // From identity mapping lookup
    GitHubUsername,  // From identity mapping lookup
    source.ip,
    source.ip.country
])
```

### GitHub Events + Identity Enrichment

```cql
source_type=github
| event.action="repo.branch_protection_rule.deleted"

// Tier 1: GitHub-specific extraction
| $github_service_account_detector()
| IsServiceAccount=false  // Filter out bots

// Extract email from GitHub sender
| UserEmail := lower(Vendor.sender.login)

// Tier 2: Universal enrichment (if email available)
| $identity_enrich_from_email()

// Now can filter based on department, privilege, etc.
| IsEngineer="True"  // Only alert on non-engineering users
| EnrichmentStatus!="none"  // Skip if no enrichment data

| select([
    @timestamp,
    UserEmail,
    Department,
    GitHubUsername,
    Vendor.sender.login,
    Vendor.repository.name,
    event.action
])
```

### Cross-Platform Username Resolution

**Use Case**: Detect same user across AWS, EntraID, and GitHub

```cql
// Start with AWS CloudTrail event
#repo=cloudtrail
| event.action="CreateAccessKey"

// Get AWS username
| $aws_enrich_user_identity()
| AWSUsername := UserIdentity

// Normalize to email and get cross-platform identities
| UserEmail := lower(UserIdentity)
| $identity_enrich_from_email()

// Now have:
//   - AWSUsername: IAM username from CloudTrail
//   - UserEmail: Email address (EntraID UPN)
//   - GitHubUsername: From identity mapping
//   - UserDisplayName: Real name

// Search for related activity across platforms
| format("Check EntraID for %s, GitHub for %s", field=[UserEmail, GitHubUsername])
```

### Universal Enrichment Output Fields Reference

**Organizational Context:**
- `UserDisplayName`: Full name
- `Department`: Department/team
- `JobTitle`: Job title
- `ManagerName`: Direct manager's name
- `ManagerEmail`: Manager's email
- `OfficeLocation`: Office or Remote

**Security Flags:**
- `IsAdmin`: Has admin privileges (bool: "True"/"False")
- `IsContractor`: External contractor (bool)
- `IsEngineer`: Engineering team member (bool)
- `IsExecutive`: Executive level (bool)
- `IsServiceAccount`: Service account (bool)
- `HasProdAccess`: Production environment access (bool)
- `HasGitHubAccess`: GitHub organization access (bool)
- `HasPIMEligibility`: Eligible for PIM activation (bool)
- `IsQuarantined`: Account quarantined (bool)

**Trust & Risk:**
- `TrustLevel`: low/medium/high/elevated
- `TrustScore`: Numeric trust score (1-10)
- `RiskScore`: Numeric risk score (0-100)
- `PrivilegeTier`: Privilege level (1-5, 1=highest)
- `AccountType`: service/user/admin/unknown

**Cross-Platform Identity Mapping:**
- `AWSUsername`: Associated AWS IAM username
- `GitHubUsername`: Associated GitHub username
- `AdminAccount`: Associated admin account (e.g., email-admin@domain.com)

**Derived Fields:**
- `UserIdentifier`: Username portion (before @)
- `UserRiskProfile`: quarantined/privileged/executive/elevated_access/external/service/standard
- `EnrichmentStatus`: full/partial/email_only/none

### When to Skip Tier 2

**SASE Events**: `$sase_enrich_user_identity()` already includes full Tier 2 enrichment

```cql
// ✅ CORRECT - SASE function already does Tier 1 + Tier 2
#Vendor="sase"
| $sase_enrich_user_identity()
| Department=*  // Already available

// ❌ WRONG - Don't call again
#Vendor="sase"
| $sase_enrich_user_identity()
| $identity_enrich_from_email()  // Unnecessary, already done
```

**Service Accounts**: No need for human identity enrichment

```cql
#repo=cloudtrail
| $aws_enrich_user_identity()
| $aws_classify_identity_type(include_service_detection="true")
| IsServiceAccount=true  // Skip Tier 2 for service accounts

// Service accounts don't need Department, JobTitle, etc.
```

**Non-Email Identifiers**: Some systems don't use email addresses

```cql
source_type=github
| Vendor.sender.login!~/@/  // Not an email address
| $identity_enrich_from_email()
| EnrichmentStatus="none"  // No match found

// Fallback to GitHub-specific context only
```

---

## Quick Reference: Tuning Checklist

### Before Tuning

- [ ] Identify vendor/data source
- [ ] Review current thresholds
- [ ] Check for existing exclusions (commented or active)
- [ ] Understand detection intent (what attack it catches)

### Apply Enrichment

- [ ] AWS: Add `$aws_enrich_user_identity()` and `$aws_classify_identity_type()`
- [ ] EntraID: Add `$entraid_enrich_user_identity()`
- [ ] GitHub: Add `$github_service_account_detector()` for bot filtering
- [ ] Network: Add `$trusted_network_detector()` or `$sase_validate_connection_source()`
- [ ] Geo: Add `$score_geo_risk()` if geographic context needed
- [ ] Cross-Platform: Add `$identity_enrich_from_email()` for universal context

### Filter Noise

- [ ] Exclude service accounts (`IsHumanIdentity=true` or `IsServiceAccount=false`)
- [ ] Exclude trusted networks (`IsExcluded=false`)
- [ ] Adjust thresholds for environment size
- [ ] Consider time-based filtering if appropriate
- [ ] Use multi-tier severity scoring for velocity-sensitive detections

### Validate

- [ ] Run `validate-query --template` to check syntax
- [ ] Review output fields for investigation context
- [ ] Confirm MITRE ATT&CK mapping still accurate
- [ ] Set appropriate severity level

---

## Template: Complete Tuned Detection

```yaml
name: "Detection Name - Tuned"
resource_id: vendor_detection_name_tuned
description: |
  [Original description]

  Tuning Applied:
  - Service account exclusion via $aws_classify_identity_type
  - Trusted network filtering via $trusted_network_detector
  - Threshold adjusted from X to Y for 500-user environment
  - Added geo-risk scoring
  - Universal identity enrichment for privilege context

severity: 50
status: active
tactic: TA00XX
technique: T1XXX
search:
  filter: |
    #repo=cloudtrail
    #Vendor=aws
    event.action="TargetAction"

    // Identity enrichment (Tier 1: AWS-specific)
    | $aws_enrich_user_identity()
    | $aws_classify_identity_type(include_service_detection="true")

    // Network validation
    | $trusted_network_detector(extend_trust="true")

    // Geographic risk
    | $score_geo_risk()

    // Core filters
    | IsHumanIdentity=true
    | IsExcluded=false
    | FinalShouldAlert=true

    // Universal enrichment (Tier 2: Cross-platform context)
    | UserEmail := lower(UserIdentity)
    | $identity_enrich_from_email()
    | IsAdmin="True"  // Filter to privileged users

    // Aggregation
    | groupBy([UserIdentity, source.ip],
        function=[
            count := count(),
            events := collect([event.action]),
            first_seen := min(@timestamp),
            last_seen := max(@timestamp)
        ])

    // Threshold
    | count >= 50

    // Output fields
    | select([
        @timestamp,
        UserEmail,
        UserDisplayName,
        Department,
        PrivilegeTier,
        IdentityCategory,
        source.ip,
        Country,
        GeoRiskCategory,
        count,
        events
    ])
  lookback: 1h0m
  trigger_mode: summary
  outcome: detection
  use_ingest_time: true
operation:
  schedule:
    definition: '@every 1h0m'
```
