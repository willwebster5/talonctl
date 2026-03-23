---
name: detection-tuning
description: Analyze CrowdStrike NGSIEM detections for tuning opportunities based on environmental context, recent false positives, and available enrichment functions. Use when tuning detections (including behavioral rules with correlate()), reducing false positives, enhancing detection coverage, or reviewing OOTB templates for production deployment.
allowed-tools: Read, Grep, Glob, Bash
---

# Detection Tuning Skill

Analyze and tune CrowdStrike NGSIEM detection rules for actionable security alerting with minimal false positives.

## Purpose

Transform raw out-of-the-box (OOTB) detection templates into production-ready rules by:
1. Applying environmental context (user population, infrastructure, baseline patterns)
2. Integrating available CQL enrichment functions for identity classification
3. Recommending threshold and exclusion tuning based on false positive patterns
4. Generating analyst-ready YAML templates

## Analysis Workflow

### Step 1: Read the Detection Template

```bash
# Read the target detection
cat resources/detections/<vendor>/<detection_file>.yaml
```

Extract and understand:
- **Vendor/Data Source**: AWS CloudTrail, EntraID, SASE, Google, CrowdStrike, GitHub
- **Detection Logic**: What events trigger alerts
- **Current Thresholds**: Count thresholds, time windows
- **Existing Exclusions**: Any commented or active filters

### Step 2: Identify Tuning Opportunities

Reference [ENVIRONMENT_CONTEXT.md](ENVIRONMENT_CONTEXT.md) to understand:
- **User Population**: ~500 users, primarily US-based across all timezones
- **High-Risk Users**: Executives and engineers (Mac users with elevated access)
- **Infrastructure**: 100% cloud (11 AWS accounts, EntraID, Google Workspace, GitHub)
- **Normal Patterns**: Business hours activity, SASE VPN connections, SSO logins
- **GitHub Activity**: Service account patterns (merge-queue, dependabot, Actions automation)
- **Statistical Baselines**: For 500-user environment, consider 30-60 day baselines for establishing normal behavior
- **Privilege Context**: TEAM users (PAM system), global admins, engineering groups with elevated access

### Step 2.5: Pre-Activation Historical Query (when activating an inactive or new detection)

**Run this step before setting `status: active` on any detection.** Skip only for detections targeting rare/clearly malicious TTPs (credential dumping, crypto miners) where expected volume is near-zero, or for log sources with fewer than 7 days of history.

**Why:** Detections can look correct in code review but still be noisy against real data. Merge exclusion bugs, missing service account filters, and overly broad regex are only visible through historical queries. A detection disabled for noise often has no documented reason — the gut feeling that something was noisy is the only signal.

#### Process

1. **Run the filter as a 30d historical query** via `ngsiem_query` with `start_time="30d"`
2. **Classify the results** — group by actor, operation type, and key event/commit pattern:
   ```
   | groupBy([actor_field, operation_field, pattern_field], function=[
       count(as=Count),
       collect([message_or_event_field], limit=10)
   ])
   | sort(Count, order=desc)
   ```
3. **Identify FP patterns** — what proportion is expected workflow vs. genuine anomaly? Common patterns:
   - High-volume actors that are automation/service accounts
   - Commit/event message patterns indicating normal operations (PR merges, sync commits, scheduled jobs)
   - Known business workflows (CI/CD deployments, admin provisioning, release processes)
4. **Propose exclusions** for FP patterns before activating — present diffs for approval
5. **Confirm acceptable volume** after exclusions applied

#### Volume Guidance (hits/30d after exclusions)

| Count | Action |
|-------|--------|
| 0–15 | Activate |
| 15–50 | Review patterns — add exclusions if FP-heavy |
| 50+ | Do not activate — filter logic needs narrowing first |

Target: 0–5 alerts/day environment-wide. A single noisy detection burns analyst time and erodes confidence in all alerts.

#### Document the Baseline

After completing pre-tuning, add a brief comment to the detection's `description` field or TUNING_BACKLOG.md:
```
# Pre-tuning baseline (YYYY-MM-DD): ~N genuine events/30d after exclusions
```

### Step 3: Apply Enrichment Functions

Reference [AVAILABLE_FUNCTIONS.md](AVAILABLE_FUNCTIONS.md) to add context. We have **38 available functions** across multiple vendors:

#### Universal Identity Enrichment

**For cross-platform identity enrichment:**
```cql
// Enrich AWS events with EntraID identity data
#repo=cloudtrail
| $aws_enrich_user_identity()
| UserEmail := lower(UserIdentity)
| $identity_enrich_from_email()
| IsAdmin="True"
| HasProdAccess="True"

// Enrich generic vendor events
| UserEmail := lower(user.email)
| $identity_enrich_from_email()
| Department=*
```

**Available function:**
- `$identity_enrich_from_email()` - Cross-platform identity enrichment (requires UserEmail field)

#### AWS Detections

**For AWS CloudTrail detections:**
```cql
// Core identity enrichment
| $aws_enrich_user_identity()
| $aws_classify_identity_type(include_service_detection="true")
| IsHumanIdentity=true  // Focus on human actors

// Service account filtering (8 service account types)
| $aws_service_account_detector()
| ServiceAccountType!="CodeBuild"  // Customize per detection

// Cross-account trust validation
| $aws_validate_cross_account_trust()
| $aws_classify_account_trust()
| TrustClassification="EXTERNAL"

// Service provider IP detection
| $aws_trusted_ip_detector()
| IsTrustedServiceIP=false

// Session context extraction
| $aws_extract_session_context()
| SessionName=*
```

**Available functions (7):**
- `$aws_enrich_user_identity()` - Extract CloudTrail user identity
- `$aws_classify_identity_type()` - Human vs service classification
- `$aws_service_account_detector()` - Detect 8 service account types (CodeBuild, Lambda, etc.)
- `$aws_validate_cross_account_trust()` - Trust relationship validation
- `$aws_classify_account_trust()` - Account trust classification (INTERNAL/EXTERNAL/UNKNOWN)
- `$aws_trusted_ip_detector()` - Service provider IP detection
- `$aws_extract_session_context()` - Session metadata extraction

#### GitHub Detections

**For GitHub push events and repository activity:**
```cql
// Core enrichment - CALL THIS FIRST
| $github_enrich_event_context()

// Service account filtering (per-detection customization)
| $github_service_account_detector()
| ServiceAccountType!="merge-queue"  // Customize based on detection needs
| ServiceAccountType!="dependabot"

// Or use all-or-nothing exclusion filtering
| $github_apply_exclusions()
| IsExcluded=false

// Risk detection (depends on github_enrich_event_context)
| $github_flag_risky_operations()
| IsRiskyOperation=true
```

**Available functions (5):**
- `$github_enrich_event_context()` - Core push event enrichment (CALL FIRST - required by other functions)
- `$github_classify_sender_type()` - Human vs bot classification
- `$github_service_account_detector()` - Per-detection service account filtering (merge-queue, dependabot, actions-bot, etc.)
- `$github_flag_risky_operations()` - Risk scoring (depends on github_enrich_event_context)
- `$github_apply_exclusions()` - All-or-nothing bot filtering

#### EntraID Detections

**For EntraID signin and audit events:**

**Basic Identity Enrichment:**
```cql
// Core identity extraction
| $entraid_enrich_user_identity()
| $entraid_classify_user_type()  // v2.0 with enhanced classification
| UserType="Employee"

// HR data enrichment
| $entraid_lookup_user_mapping()
| Department=*
| IsActive="True"
```

**Group & Privilege Analysis:**
```cql
// Comprehensive group membership
| $entraid_enrich_group_summary()
| TotalGroups > 0

// Check privileged groups (tier-based)
| $entraid_check_privileged_groups(strict_mode="true")
| IsPrivilegedUser=true
| PrivilegeTier=*

// Check TEAM (PAM) eligibility
| $entraid_check_team_eligibility()
| TEAMViolation=true

// Validate department access patterns
| $entraid_validate_department_access(validate_technical="true")
| DepartmentAccessViolation=true
```

**Authorization Context:**
```cql
// Trust level enrichment
| $entraid_lookup_trust_level()
| TrustLevel=*

// Authorization context
| $entraid_add_authorization_context()
| AuthorizationContext=*

// Policy violation detection
| $entraid_flag_unauthorized_actions()
| IsUnauthorized=true

// Admin enforcement filter
| $entraid_require_admin_authorization()
| RequiresAdminAuth=true
```

**Investigative Functions (Parameterized):**
```cql
// Full signin audit for specific user
| $entraid_user_signin_audit(user="user@example.com")

// Device inventory for user
| $entraid_user_device_summary(user="user@example.com")

// Mobile signin history
| $entraid_user_mobile_signins(user="user@example.com")

// Unregistered device detection
| $entraid_user_unregistered_devices(user="user@example.com")
```

**Available functions (15):**

*Basic Identity:*
- `$entraid_enrich_user_identity()` - Extract user identity
- `$entraid_classify_user_type()` - v2.0 enhanced classification (service/contractor/employee)
- `$entraid_lookup_user_mapping()` - HR data enrichment

*Group & Privilege:*
- `$entraid_enrich_group_summary()` - Comprehensive group analysis
- `$entraid_check_privileged_groups()` - Privilege tier checking (strict_mode parameter)
- `$entraid_check_team_eligibility()` - TEAM/PIM eligibility tracking
- `$entraid_validate_department_access()` - Department hierarchy validation

*Authorization:*
- `$entraid_lookup_trust_level()` - Trust level enrichment
- `$entraid_add_authorization_context()` - Auth context enrichment
- `$entraid_flag_unauthorized_actions()` - Policy violation detection
- `$entraid_require_admin_authorization()` - Admin enforcement filter

*Investigative (parameterized):*
- `$entraid_user_signin_audit(user)` - Full signin audit trail
- `$entraid_user_device_summary(user)` - Device inventory
- `$entraid_user_mobile_signins(user)` - Mobile signin history
- `$entraid_user_unregistered_devices(user)` - Unregistered device detection

#### Network-Based Detections

**For SASE SASE and network traffic:**
```cql
// Trusted network detection (SASE VPN)
| $trusted_network_detector(extend_trust="true", include_private="true")
| IsExcluded=false  // Filter out SASE VPN traffic

// SASE + EntraID enrichment (30+ fields)
| $sase_enrich_user_identity()
| UserEmail=*

// Connection source validation
| $sase_validate_connection_source()
| IsValidConnectionSource=true

// Geographic risk scoring
| $score_geo_risk()
| FinalShouldAlert=true
```

**Available functions (4):**
- `$trusted_network_detector()` - SASE VPN filtering (extend_trust, include_private parameters)
- `$sase_enrich_user_identity()` - SASE + EntraID enrichment (30+ fields)
- `$sase_validate_connection_source()` - Connection source validation
- `$score_geo_risk()` - Geographic risk scoring

#### Statistical Baseline Detection

**For establishing normal behavior baselines:**
```cql
// Establish 30-day baseline
| defineTable("baseline_stats", [
    groupBy([EntityId, EventType], function=[
        avg(HourlyCount, as=BaselineAvg),
        stddev(HourlyCount, as=BaselineStdDev)
    ])
], lookbackDays=30, excludeStart=2h)

// Calculate dynamic threshold
| match(file="baseline_stats", field=[EntityId, EventType])
| Threshold := BaselineAvg + 3 * BaselineStdDev
| test(CurrentCount > Threshold)

// Or use pre-built baseline functions
| $create_baseline_60d()  // 60-day lookback
```

**Available functions (3):**
- `$create_baseline_7d()` - 7-day historical baseline
- `$create_baseline_60d()` - 60-day historical baseline
- `$create_baseline_90d()` - 90-day historical baseline

### Step 4: Generate Tuned Output

Produce three deliverables:

1. **Analysis Report**: Document findings and rationale
2. **Tuning Recommendations**: Specific CQL snippets with explanations
3. **Production-Ready YAML**: Complete template ready for deployment

#### Standard Detection Format

```yaml
name: "Detection Name - Tuned"
resource_id: detection_resource_id
description: |
  [Enhanced description with tuning notes]

  Tuning Applied:
  - [List of tuning changes]

severity: [Adjusted severity 5-90]
status: active
mitre_attack: ["TA00XX:T1XXX"]  # Format: ["Tactic (TAXXXX):Technique: Sub-technique (T1XXX.YYY)"]
search:
  filter: |
    [Tuned query with enrichment functions]
  lookback: [Adjusted time window]
  trigger_mode: summary
  outcome: detection
operation:
  schedule:
    definition: '@every [frequency]'
```

#### Multi-Tier Severity Detection Format

For detections with different severity levels based on threshold/context:

```yaml
name: "Detection Name - Multiple Thresholds"
resource_id: detection_multi_tier
severity: 50  # Default STANDARD tier
description: |
  Detection with tiered thresholds for different attack patterns:
  - RAPID: High-confidence attacks (Severity 70) - 3+ events in 15 minutes
  - STANDARD: Balanced detection (Severity 50) - 5+ events in 30 minutes
  - SUSTAINED: Slow attacks (Severity 40) - 8+ events in 60 minutes

  Tuning Applied:
  - Multi-tier severity based on velocity
  - Service account exclusions
  - Geographic risk scoring

severity: 50
status: active
mitre_attack: ["TA0001:T1078"]
search:
  filter: |
    #repo=cloudtrail event.name="ConsoleLogin"
    | $aws_enrich_user_identity()
    | $aws_classify_identity_type(include_service_detection="true")
    | IsHumanIdentity=true

    // Count events per user
    | groupBy([UserIdentity], function=[count(as=Count)])

    // Calculate time window
    | DurationMinutes := duration(start=_earliest, end=_latest, unit="minutes")

    // Multi-tier severity
    | case {
        test(Count >= 3) test(DurationMinutes <= 15) | Severity := 70 | Tier := "RAPID";
        test(Count >= 5) test(DurationMinutes <= 30) | Severity := 50 | Tier := "STANDARD";
        test(Count >= 8) test(DurationMinutes <= 60) | Severity := 40 | Tier := "SUSTAINED";
        * | Severity := 0;
    }
    | Severity > 0
  lookback: 2h
  trigger_mode: summary
  outcome: detection
operation:
  schedule:
    definition: '@every 15m'
```

### Step 5: Behavioral Rule Tuning (for correlate() rules)

For behavioral rules using `correlate()`, additional tuning considerations apply:

**Time Window Optimization (`within`):**
```cql
correlate(
  EventA: { ... },
  EventB: { ... | field <=> EventA.field },
  within=30m  // Tune based on expected attack duration
)
```
- Too narrow: May miss legitimate attack chains
- Too wide: Increases false positives from unrelated events

**Sequence Enforcement (`sequence`):**
- Use `sequence=true` only when event order is attack-relevant
- Non-sequence mode is more flexible for correlation

**Output Outcome Types:**
| Outcome | Field Value | Use Case |
|---------|-------------|----------|
| Behavioral Detection | `Ngsiem.event.outcome="behavioral-detection"` | Multi-event attack patterns |
| Correlation Rule Detection | `Ngsiem.event.outcome="correlation-rule-detection"` | Single-event threshold rules |
| Behavioral Case | `Ngsiem.event.outcome="behavioral-case"` | Case-generating rules |

**Behavioral Rule YAML Template:**
```yaml
name: "Behavioral Detection - Attack Chain"
resource_id: behavioral_attack_chain
severity: 70
search:
  filter: |
    correlate(
      Step1: { ... },
      Step2: { ... | field <=> Step1.field },
      sequence=true,
      within=1h,
      globalConstraints=[user.email]
    )
  lookback: 4h  # Should exceed 'within' parameter
  trigger_mode: summary
  outcome: detection  # or 'case' for behavioral-case
```

## Output Format

### Analysis Report Structure

```markdown
## Detection Analysis: [Detection Name]

### Overview
- **Vendor**: [AWS/EntraID/SASE/GitHub/etc.]
- **Threat**: [What attack this detects]
- **MITRE ATT&CK**: [Tactic/Technique]

### Current State
- Query logic summary
- Current thresholds
- Identified issues

### Environmental Considerations
- Relevant user patterns from [ENVIRONMENT_CONTEXT.md]
- Expected false positive sources
- High-value targets affected
- Statistical baseline recommendations (30-60 day for 500-user environment)

### Recommendations
1. [Recommendation with CQL snippet]
2. [Recommendation with CQL snippet]
...

### Risk Assessment
- False positive risk: [Low/Medium/High]
- Detection coverage: [What it catches vs misses]
- Recommended severity: [Adjusted severity with rationale]
```

### Multi-Event Correlation Output

For complex correlations across multiple event types:

```yaml
name: "Behavioral Detection - Multi-Stage Attack"
resource_id: multi_stage_attack
severity: 80
mitre_attack: ["TA0001:T1078.004", "TA0004:T1068", "TA0010:T1537"]
description: |
  Detects multi-stage attack pattern across AWS and EntraID:
  1. Initial access via console login
  2. Privilege escalation within 1 hour
  3. Data exfiltration activity

  Correlation window: 2 hours
  Minimum events: 3 distinct stages

search:
  filter: |
    // Stage 1: Console login
    correlate(
      Stage1: {
        #repo=cloudtrail event.name="ConsoleLogin"
        | $aws_enrich_user_identity()
        | IsHumanIdentity=true
      },
      Stage2: {
        #repo=cloudtrail event.name=/AttachUserPolicy|PutUserPolicy/
        | $aws_enrich_user_identity()
        | field <=> Stage1.UserIdentity
      },
      Stage3: {
        #repo=cloudtrail event.name=/GetObject|DownloadDBSnapshot/
        | $aws_enrich_user_identity()
        | field <=> Stage1.UserIdentity
      },
      sequence=true,
      within=2h,
      globalConstraints=[UserIdentity]
    )
  lookback: 4h
  trigger_mode: summary
  outcome: detection
```

## Tuning Decision Framework

### When to Exclude vs Alert

| Scenario | Action | Rationale |
|----------|--------|-----------|
| Known service account | Exclude | Automation noise |
| SASE VPN traffic | Exclude | Corporate network |
| GitHub merge-queue bot | Exclude | Automated merges |
| Root account usage | Alert (Critical) | Always investigate |
| After-hours admin activity | Alert | Unusual timing |
| Executive account anomaly | Alert (High) | High-value target |
| Failed auth from unknown country | Alert | Geo anomaly |
| TEAM policy violation | Alert | PAM policy breach |

### Threshold Guidelines

Based on environment (500 users, 0-5 alerts/day target):

| Detection Type | Suggested Threshold | Notes |
|----------------|---------------------|-------|
| Brute force | 50+ failures OR 10+ accounts | Reduce noise |
| Data exfil | 100GB+ or 10x baseline | High threshold |
| Privilege escalation | Any occurrence | Low threshold |
| Config change | Based on baseline | Use defineTable |
| GitHub force push | 3+ in 1 hour | Filter merge-queue |
| Admin signin anomaly | Any from new country | Geo-risk + privilege |

### Severity Mapping

| CrowdStrike Severity | When to Use |
|----------------------|-------------|
| 90 (Critical) | Root account, production compromise |
| 70 (High) | Admin privilege abuse, exec targeting |
| 50 (Medium) | Suspicious patterns, policy violations |
| 30 (Low) | Informational, baseline deviations |
| 5-10 (Informational) | Audit/compliance events |

## Function Quick Reference

### Universal Identity (1 function)
- `$identity_enrich_from_email()` - Cross-platform identity enrichment (requires UserEmail)

### AWS Functions (7 functions)
- `$aws_enrich_user_identity()` - Extract CloudTrail identity
- `$aws_classify_identity_type()` - Human vs service classification
- `$aws_service_account_detector()` - 8 service account types
- `$aws_validate_cross_account_trust()` - Trust relationship validation
- `$aws_classify_account_trust()` - Account trust classification
- `$aws_trusted_ip_detector()` - Service provider IP detection
- `$aws_extract_session_context()` - Session metadata

### GitHub Functions (5 functions)
- `$github_enrich_event_context()` - Core push event enrichment (call first)
- `$github_classify_sender_type()` - Human vs bot classification
- `$github_service_account_detector()` - Per-detection service account filtering
- `$github_flag_risky_operations()` - Risk scoring (depends on github_enrich_event_context)
- `$github_apply_exclusions()` - All-or-nothing bot filtering

### EntraID Functions (15 functions)

**Basic Identity (3):**
- `$entraid_enrich_user_identity()` - Extract user identity
- `$entraid_classify_user_type()` - v2.0 enhanced classification (service/contractor/employee)
- `$entraid_lookup_user_mapping()` - HR data enrichment

**Group & Privilege (4):**
- `$entraid_enrich_group_summary()` - Comprehensive group analysis
- `$entraid_check_privileged_groups()` - Privilege tier checking
- `$entraid_check_team_eligibility()` - TEAM/PIM eligibility tracking
- `$entraid_validate_department_access()` - Department hierarchy validation

**Authorization (4):**
- `$entraid_lookup_trust_level()` - Trust level enrichment
- `$entraid_add_authorization_context()` - Auth context enrichment
- `$entraid_flag_unauthorized_actions()` - Policy violation detection
- `$entraid_require_admin_authorization()` - Admin enforcement filter

**Investigative (4 - parameterized):**
- `$entraid_user_signin_audit(user)` - Full signin audit trail
- `$entraid_user_device_summary(user)` - Device inventory
- `$entraid_user_mobile_signins(user)` - Mobile signin history
- `$entraid_user_unregistered_devices(user)` - Unregistered device detection

### Network Functions (4 functions)
- `$trusted_network_detector()` - SASE VPN filtering
- `$sase_enrich_user_identity()` - SASE + EntraID enrichment (30+ fields)
- `$sase_validate_connection_source()` - Connection source validation
- `$score_geo_risk()` - Geographic risk scoring

### Baseline Functions (3 functions)
- `$create_baseline_7d()` - 7-day historical baseline
- `$create_baseline_60d()` - 60-day historical baseline
- `$create_baseline_90d()` - 90-day historical baseline

**Total: 38 available functions**

## Common Tuning Patterns

Reference [TUNING_PATTERNS.md](TUNING_PATTERNS.md) for detailed examples:

1. **Service Account Exclusion**: Filter automated activities (AWS, GitHub, EntraID)
2. **Trusted Network Filtering**: Exclude SASE/internal traffic
3. **Identity Enrichment Pipeline**: Add user context before alerting
4. **Threshold Tuning**: Adjust counts based on environment size
5. **Time-based Filtering**: Business hours vs after-hours
6. **Geo-risk Assessment**: US-only workforce context
7. **Behavioral Rule Time Windows**: Optimize `within` for attack patterns
8. **Sequence vs Non-Sequence**: Choose based on attack chain requirements
9. **Statistical Baselines**: 30-60 day lookbacks for 500-user environment
10. **Multi-Tier Severity**: Different thresholds for different attack velocities
11. **Privilege Context Filtering**: TEAM users, global admins, technical groups
12. **Cross-Platform Correlation**: AWS + EntraID identity enrichment

## Real Detection Examples

Reference [EXAMPLES.md](EXAMPLES.md) for real detection templates in the codebase:

| Detection Type | Example File |
|----------------|--------------|
| Brute force (threshold tuning) | `resources/detections/aws/aws___cloudtrail___potential_brute_force_attack_on_iam_users_via_aws_management_console.yaml` |
| SSO issues (risk scoring) | `resources/detections/microsoft/microsoft_entra_id_macos_platform_sso_token_failure.yaml` |
| Root account (critical alert) | `resources/detections/aws/aws___cloudtrail___console_root_login.yaml` |

Browse all detections:
```bash
ls resources/detections/aws/
ls resources/detections/microsoft/
ls resources/detections/github/
```

Browse all saved search functions:
```bash
ls resources/saved_searches/
```

## Query Validation

**CRITICAL**: Always validate CQL query syntax before presenting tuned detections.

### Validation Command

```bash
# Validate query from template file
python scripts/resource_deploy.py validate-query --template <path>

# Validate inline query directly
python scripts/resource_deploy.py validate-query --query '<cql_query>'
```

### Validation Output

| Result | Exit Code | Meaning |
|--------|-----------|---------|
| `VALID` | 0 | Query syntax is correct |
| `INVALID: <message>` | 1 | Syntax error with details |

### Common CQL Syntax Errors

**1. Case Statement Syntax**
```cql
// WRONG - missing semicolons
| case {
    condition1 | action1
    condition2 | action2
    * | default
}

// CORRECT - semicolons after each branch
| case {
    condition1 | action1;
    condition2 | action2;
    * | default;
}
```

**2. test() Function Usage**
```cql
// WRONG - comparison without test()
| AdjustedGeoRisk >= 80

// CORRECT - numeric comparisons need test()
| test(AdjustedGeoRisk >= 80)

// EXCEPTION - equality checks don't need test()
| IsHumanIdentity=true  // OK without test()
```

**3. Regex Syntax**
```cql
// WRONG - quotes around regex
| field=~"/pattern/"

// CORRECT - no quotes for regex
| field=~/pattern/

// CORRECT - named capture groups
| field=/prefix(?<captured>pattern)suffix/
```

**4. in() Function Syntax**
```cql
// WRONG - field as string
| in(field="Country", values=["US", "Canada"])

// CORRECT - field without quotes
| in(field=Country, values=["US", "Canada"])
```

**5. Function Parameters**
```cql
// WRONG - boolean parameter
| $aws_classify_identity_type(include_service_detection=true)

// CORRECT - string parameter
| $aws_classify_identity_type(include_service_detection="true")
```

**6. Field Assignment**
```cql
// WRONG - equals for assignment
| NewField = value

// CORRECT - := for assignment
| NewField := value
```

**7. Negation Patterns**
```cql
// Filter syntax options
| field != "value"           // Not equal
| field!="value"             // Also valid
| NOT field="value"          // NOT operator
| field=~!/pattern/          // Negative regex match
```

### Advanced Validation Notes

**Statistical Baseline Validation:**
```cql
// defineTable() syntax requirements
| defineTable("baseline_stats", [
    groupBy([EntityId, EventType], function=[
        avg(HourlyCount, as=BaselineAvg)
    ])
], lookbackDays=30, excludeStart=2h)  // lookbackDays must be > 0

// CRITICAL: excludeStart/excludeEnd must be < lookbackDays
// CRITICAL: match() field list must match defineTable groupBy fields
| match(file="baseline_stats", field=[EntityId, EventType])
```

**Multi-Event Correlation Validation:**
```cql
// bucket(span=Xm) pattern
| bucket(span=5m)  // span should match detection time window

// Object traversal syntax for nested arrays
| objectArray:eval {
    nestedField=*
}

// Time window sizing: balance correlation window vs performance
// Rule: correlation window should be < 4 hours for performance
```

**Function Dependencies:**
```cql
// WRONG - calling github_flag_risky_operations without prerequisite
| $github_flag_risky_operations()  // ERROR: requires github_enrich_event_context

// CORRECT - call prerequisite first
| $github_enrich_event_context()
| $github_flag_risky_operations()

// WRONG - calling EntraID group functions without identity
| $entraid_check_privileged_groups()  // ERROR: requires UserEmail

// CORRECT - enrich identity first
| $entraid_enrich_user_identity()
| $entraid_check_privileged_groups()
```

**Complexity Indicators:**
- Functions with dependencies must be called in order
- GitHub: `github_flag_risky_operations()` requires `github_enrich_event_context()`
- EntraID: Group/privilege functions require UserEmail from `enrich_user_identity()`
- AWS: Service account detection requires `classify_identity_type()` first
- Universal: `identity_enrich_from_email()` requires UserEmail field

### Validation Workflow

1. **Before presenting tuned query**: Run `validate-query --template`
2. **If INVALID**: Fix the syntax error and re-validate
3. **If VALID**: Include in analysis report and tuned YAML
4. **After writing YAML file**: Run validation again to confirm
5. **Check function dependencies**: Ensure prerequisite functions are called first

### Plan Deployment (Dry Run)

After validation passes, test the full deployment:

```bash
# Plan without applying (safe, read-only)
python scripts/resource_deploy.py plan --resources=detection

# Validate all templates
python scripts/resource_deploy.py validate
```

## Important Notes

- **Always validate CQL syntax** before recommending - never present unvalidated queries
- **Check function dependencies** - some functions require others to be called first
- Preserve original detection intent while reducing noise
- Document all tuning decisions for audit trail
- Consider MITRE ATT&CK coverage implications
- Test with recent data before production deployment
- If validation fails, fix and re-validate before continuing
- For 500-user environments, 30-60 day baselines are recommended
- Multi-tier severity can provide better context for different attack patterns
- Cross-platform enrichment (AWS + EntraID) provides deeper identity context

## Creating New Saved Search Functions

When tuning requires a new saved search function (not in [AVAILABLE_FUNCTIONS.md](AVAILABLE_FUNCTIONS.md)):

1. **Create the function** in `resources/saved_searches/`
2. **Deploy the function FIRST** before using it in detections:
   ```bash
   python scripts/resource_deploy.py apply --resources=saved_search --names="<function_name>" --auto-approve
   ```
3. **Then validate** detections that use the new function - validation calls the LogScale API which requires the function to exist
4. **Update documentation** in `AVAILABLE_FUNCTIONS.md` with the new function

**Why?** Query validation uses the LogScale API to check syntax. If a detection references `$my_new_function()` that doesn't exist in LogScale yet, validation will fail with "Unknown error" even if the syntax is correct.
