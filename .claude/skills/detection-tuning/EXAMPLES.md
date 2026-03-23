# Detection Examples Reference

This document references real detection templates in the codebase as examples of tuning patterns and query structures.

---

## Detection Examples by Pattern Category

Quick navigation to examples by advanced tuning technique:

- **[Service Account Filtering](#example-1-github---multiple-branch-deletions)**: GitHub Multiple Branch Deletions
- **[Statistical Baselines](#example-2-aws-cloudtrail---kms-anomalous-data-key-generation)**: AWS KMS Anomalous Data Key Generation, Anomalous USB Exfiltration
- **[Multi-Tier Severity](#example-3-microsoft-entraid---multiple-failed-login-optimized)**: EntraID Multiple Failed Login (Optimized)
- **[Geographic Intelligence](#example-4-microsoft-entraid---unauthorized-international-sign-in)**: EntraID Unauthorized International Sign-in
- **[Simple Aggregation](#simple-threshold-tuning-aws-brute-force-detection)**: AWS Brute Force Detection
- **[Risk Scoring](#macOS-platform-sso-detection-risk-scoring)**: macOS Platform SSO Token Failure

---

## Advanced Detection Examples

These examples demonstrate production-ready detection patterns with sophisticated tuning techniques.

---

### Example 1: GitHub - Multiple Branch Deletions

**File**: `resources/detections/github/github___multiple_branch_deletions.yaml`

**Purpose**: Detect when a single user deletes 3 or more branches within a 1-hour period. While branch cleanup is normal, bulk deletions could indicate a compromised account attempting to destroy code or an insider performing destructive actions.

**Risk**: Code destruction, sabotage, compromised credentials

**Tuning Techniques Applied**:

1. **Service Account Filtering with Per-Detection Customization**
   - Uses `$github_service_account_detector()` to identify service accounts
   - **Key Innovation**: Excludes only merge-queue bot, not all bots
   - Allows legitimate automation (Dependabot, renovate) while filtering noise
   - Demonstrates selective service account exclusion vs blanket filtering

2. **Simple Threshold Aggregation**
   - Groups by user and organization
   - Threshold: 3+ deletions in 1 hour
   - Uses `test()` function for clean filtering

**Complete CQL Query**:

```cql
source_type=github
| Vendor.deleted="true"
| Vendor.sender.login=*

// Filter service accounts - exclude merge queue bot (customize per detection)
| $github_service_account_detector()
| ServiceAccountType!="merge-queue"

// Aggregate by user
| groupBy([Vendor.sender.login, Vendor.organization.login], function=count(as=DeletionCount))
| test(DeletionCount >= 3)
```

**Output Fields**:
- `Vendor.sender.login` - User who deleted branches
- `Vendor.organization.login` - GitHub organization
- `DeletionCount` - Number of branch deletions
- `ServiceAccountType` - Service account classification (if matched)

**Why This Works**:

This detection demonstrates **contextual service account filtering** - rather than excluding all service accounts, it applies business logic:
- Merge queue bots frequently delete temporary branches (expected behavior)
- Other bots (Dependabot, renovate) rarely delete branches (worth alerting on)
- Humans bulk-deleting branches is suspicious

The pattern shows how to **customize enrichment function output** per detection rather than applying blanket exclusions.

**Tuning Considerations**:
- Adjust threshold based on team size and branch management practices
- For monorepos with heavy automation, increase threshold to 5-7
- Consider adding time-of-day logic (deletions at 3 AM more suspicious)
- Can combine with GitHub app context to exclude specific automation tools

---

### Example 2: AWS CloudTrail - KMS Anomalous Data Key Generation

**File**: `resources/detections/aws/aws_cloudtrail_kms_anomalous_data_key_generation.yaml`

**Purpose**: Detect unusual volume of KMS GenerateDataKey operations by comparing current behavior against a 30-day historical baseline. Identifies when users or roles generate data keys in patterns that deviate from their established behavior, potentially indicating unauthorized data encryption attempts, suspected data exfiltration preparation, or possible cryptographic operations by compromised credentials.

**Tuning Techniques Applied**:

1. **Statistical Baseline with defineTable()**
   - 30-day historical baseline (excluding last 70 minutes)
   - Identifies "frequent generators" (>10 key generations in baseline)
   - Per-identity + per-KMS-key baseline tracking

2. **Service Account Detection with Confidence Levels**
   - Uses `$aws_service_account_detector(strict_mode="true", include_temp="false")`
   - Excludes high-confidence service accounts (hawk-service, cicd)
   - Maintains alerts for lower-confidence classifications

3. **Baseline Comparison Logic**
   - Alerts on users NOT in baseline (new behavior)
   - Alerts on users in baseline but not frequent generators (volume change)
   - Ignores established frequent generators (normal automation)

**Complete CQL Query** (Key Sections):

```cql
// Step 1: Build baseline table
defineTable(
    query={
        #Vendor="aws" #event.module="cloudtrail" #repo!="xdr*"
        | #event.kind="event" #event.outcome="success"
        | event.provider="kms.amazonaws.com"
        | event.action =~ in(values=["GenerateDataKey", "GenerateDataKeyWithoutPlaintext",
                                      "GenerateDataKeyPair", "GenerateDataKeyPairWithoutPlaintext"])
        | Vendor.userIdentity.arn=*
        | user.name=*
        | _identity := coalesce([Vendor.userIdentity.arn, user.id])
        | groupBy([_identity, user.name, Vendor.requestParameters.keyId],
                  function=[count(as="_baseline_count")])
        | case {
            // TUNING: Adjust threshold based on normal key generation patterns
            _baseline_count > 10 | _frequent_generator := true;
            * | _frequent_generator := false
        }
    },
    include=[_identity, user.name, Vendor.requestParameters.keyId, _frequent_generator],
    name="kms_key_generation",
    start=30d,
    end=70m
)

// Step 2: Query current activity
| #Vendor="aws" #event.module="cloudtrail" #repo!="xdr*"
| #event.kind="event" #event.outcome="success"
| event.provider="kms.amazonaws.com"
| event.action =~ in(values=["GenerateDataKey", "GenerateDataKeyWithoutPlaintext",
                              "GenerateDataKeyPair", "GenerateDataKeyPairWithoutPlaintext"])
| Vendor.userIdentity.arn=*
| user.name=*

// Step 3: Apply service account detection and filter
| $aws_service_account_detector(strict_mode="true", include_temp="false")
| NOT in(ServiceAccountType, values=["hawk-service", "cicd"])
// TUNING: Exclude known service principals with Secrets Manager access
| user.name =~ !in(values=["awsreservedsso_team_secretsmanagement*", "*codebuild-assume-role"])

// Step 4: Match against baseline
| _identity := coalesce([Vendor.userIdentity.arn, user.id])
| match(file="kms_key_generation", field=[_identity, user.name, Vendor.requestParameters.keyId], strict=false)

// Step 5: Alert on anomalous patterns
| case {
    _frequent_generator=false;  // User in baseline but not a frequent generator
    _frequent_generator!=*;     // User not in baseline at all (new behavior)
}

// Step 6: Aggregate and output
| groupBy([user.name, event.provider, event.action, Vendor.requestParameters.keyId],
         function=collect([event.provider, user.name, user.id, event.action,
                          _frequent_generator, Vendor.requestParameters.keyId,
                          cloud.region, user_agent.original, ServiceAccountType, DetectionConfidence]))
```

**Statistical Baseline Pattern Breakdown**:

1. **Historical Window**: `start=30d, end=70m`
   - 30 days provides stable baseline
   - 70-minute exclusion prevents current events from contaminating baseline
   - Matches 1-hour schedule + 10-minute ingestion buffer

2. **Frequency Classification**: `_baseline_count > 10`
   - Identifies "frequent generators" (automation, regular users)
   - Threshold tunable based on environment (10 is conservative)
   - Prevents alerts on normal high-volume users

3. **Match Logic**: `strict=false`
   - Allows unmatched records through (new behavior detection)
   - Matched records get `_frequent_generator` field
   - Unmatched records have `_frequent_generator!=*` (null check)

4. **Alert Conditions**:
   - New behavior: User never seen in 30-day baseline
   - Changed behavior: User exists but volume increased significantly

**Output Fields**:
- `user.name`, `user.id` - Identity context
- `event.action` - Specific KMS operation
- `Vendor.requestParameters.keyId` - KMS key used
- `_frequent_generator` - Baseline classification
- `ServiceAccountType` - Service account category
- `DetectionConfidence` - Confidence level of service account classification
- `cloud.region` - AWS region
- `user_agent.original` - Client context

**Why This Works**:

This detection uses **personalized statistical baselines** rather than fixed thresholds:
- **Traditional approach**: "Alert on >50 KMS operations per hour" → Misses low-volume attacks, noisy for automation
- **Baseline approach**: "Alert when behavior deviates from 30-day normal" → Adapts to each identity's patterns

The `defineTable()` pattern is powerful for:
- **Zero false positives on automation**: Frequent generators are learned and excluded
- **High sensitivity to anomalies**: Any deviation from established patterns triggers
- **Automatic adaptation**: Baseline updates daily without manual tuning

**Tuning Considerations**:
- **Baseline window**: 30 days balances stability vs recency (adjust to 14d for faster adaptation)
- **Frequency threshold**: 10 is conservative (increase to 20-50 for high-automation environments)
- **Service account exclusions**: Add organization-specific service principals to filter list
- **Alert conditions**: Can add `_baseline_count` comparison for "X times above normal" logic

---

### Example 3: Microsoft EntraID - Multiple Failed Login (Optimized)

**File**: `resources/detections/microsoft/microsoft_entra_id_multiple_failed_login_optimized.yaml`

**Purpose**: Detect brute force attacks against EntraID accounts with three severity tiers optimized for different attack patterns. Provides rapid detection (15-minute schedule) with sophisticated temporal gating to prevent duplicate alerts while maintaining comprehensive context collection.

**Status**: Testing (runs parallel to standard failed login detection for validation)

**Tuning Techniques Applied**:

1. **Multi-Tier Detection Thresholds**
   - RAPID: 3+ failures in 15min → Severity 70 (high confidence attacks)
   - STANDARD: 5+ failures in 30min → Severity 50 (balanced detection)
   - SUSTAINED: 8+ failures in 1h → Severity 40 (low/slow attacks)

2. **Temporal Gating for Duplicate Prevention**
   - 20-minute alert window prevents duplicate alerts
   - Only alerts if `LastAttempt > (now() - 20m)`
   - Accounts for 15m schedule + 5m ingestion delay

3. **Velocity Pre-calculation**
   - Calculates attack velocity before case statements
   - Avoids arithmetic operations in case conditions (CQL limitation)
   - Pattern: `_velocity_calc := TotalFailures / AttackDurationMinutes`

4. **Risk Score Escalation (6 Tiers)**
   - Base tier risk: 90/80/70/60/55/50
   - Escalation factors: Multiple IPs (+10-20), multiple apps (+5), high velocity (+10)
   - Composite scoring for accurate threat assessment

5. **Attack Pattern Classification**
   - Distributed attack: Multiple IPs + multiple devices
   - Credential spray: Multiple IPs + same device
   - Device compromise: Same IP + multiple devices
   - Multi-app spray: 2+ applications targeted
   - High-velocity: >1 failure per minute

**Key CQL Patterns** (Extracted from 280-line query):

```cql
// ============================================
// AGGREGATION - Group by user with rich context
// ============================================

| groupBy([user.name], function=[
    // Core metrics
    count(_event_id, as=TotalFailures, distinct=true),

    // Temporal tracking
    min(@timestamp, as=FirstAttempt),
    max(@timestamp, as=LastAttempt),

    // Source diversity (attack indicators)
    count(source.ip, as=UniqueIPs, distinct=true),
    collect([source.ip], limit=10),

    // User context
    selectLast([user.id, user.full_name]),

    // Application targets
    count(Vendor.properties.appDisplayName, as=UniqueApps, distinct=true),
    collect([Vendor.properties.appDisplayName], limit=5),

    // Device diversity
    count(Vendor.properties.deviceDetail.deviceId, as=UniqueDevices, distinct=true),
    collect([Vendor.properties.deviceDetail.displayName], limit=5),

    // Network context
    collect([IsSaseNetwork], limit=3),

    // Failure details for investigation
    collect([Vendor.properties.status.additionalDetails], limit=3)
  ])

// ============================================
// TIME WINDOW CALCULATIONS - Post-aggregation
// ============================================

// Calculate current time reference
| _current_time := now()

// Calculate attack characteristics
| AttackDuration := (LastAttempt - FirstAttempt)
| AttackDurationMinutes := AttackDuration / 60000

// Calculate time since last attempt
| TimeSinceLastMinutes := (_current_time - LastAttempt) / 60000

// Pre-calculate velocity components (IMPORTANT: avoid arithmetic in case statements)
| _velocity_calc := TotalFailures / AttackDurationMinutes
| _failures_15m_ratio := TotalFailures * 15 / AttackDurationMinutes
| _failures_30m_ratio := TotalFailures * 30 / AttackDurationMinutes

// Calculate attack velocity (failures per minute)
| case {
    AttackDurationMinutes > 0 | AttackVelocity := _velocity_calc;
    * | AttackVelocity := TotalFailures;
  }

// Estimate failures in 15-minute window based on attack pattern
| case {
    TimeSinceLastMinutes <= 15 AND AttackDurationMinutes <= 15 | Failures_15m := TotalFailures;
    TimeSinceLastMinutes <= 15 AND AttackDurationMinutes > 15 | Failures_15m := _failures_15m_ratio;
    * | Failures_15m := 0;
  }

// Estimate failures in 30-minute window based on attack pattern
| case {
    TimeSinceLastMinutes <= 30 AND AttackDurationMinutes <= 30 | Failures_30m := TotalFailures;
    TimeSinceLastMinutes <= 30 AND AttackDurationMinutes > 30 | Failures_30m := _failures_30m_ratio;
    * | Failures_30m := 0;
  }

// Round to integers for cleaner display
| Failures_15m := math:floor(Failures_15m)
| Failures_30m := math:floor(Failures_30m)

// ============================================
// THRESHOLD LOGIC - Multi-tier detection
// ============================================

// Assign detection tier based on velocity and volume
| case {
    Failures_15m >= 3 | DetectionTier := "RAPID" | Severity := 70 | ConfidenceLevel := "High";
    Failures_30m >= 5 | DetectionTier := "STANDARD" | Severity := 50 | ConfidenceLevel := "Medium";
    TotalFailures >= 8 | DetectionTier := "SUSTAINED" | Severity := 40 | ConfidenceLevel := "Medium";
    * | DetectionTier := "BELOW_THRESHOLD" | Severity := 0;
  }

// Refilter based on new severity
| Severity > 0

// ============================================
// TEMPORAL GATING - Prevent duplicate alerts
// ============================================

// Only alert if attack activity occurred within last 20 minutes
// This prevents duplicate detections on same events across multiple executions
// 20m = 15m schedule + 5m grace period for late-arriving events
| _alert_window_ms := 20 * 60 * 1000  // 20 minutes in milliseconds
| _cutoff_time := _current_time - _alert_window_ms
| test(LastAttempt > _cutoff_time)

// Add recency indicator for SOC context
| MinutesSinceLastAttempt := TimeSinceLastMinutes
| MinutesSinceLastAttempt := format("%0.1f", field=MinutesSinceLastAttempt)

// ============================================
// RISK SCORING - 6-tier escalation
// ============================================

// Attack pattern classification
| case {
    UniqueIPs > 1 AND UniqueDevices > 1 | AttackPattern := "Distributed/Multiple Sources";
    UniqueIPs > 1 AND UniqueDevices = 1 | AttackPattern := "Multiple IPs/Same Device";
    UniqueIPs = 1 AND UniqueDevices > 1 | AttackPattern := "Same IP/Multiple Devices";
    UniqueApps > 2 | AttackPattern := "Multi-Application Spray";
    AttackVelocity > 1.0 | AttackPattern := "High-Velocity Attack";
    * | AttackPattern := "Single Source/Standard";
  }

// Risk scoring enhancement
| case {
    DetectionTier = "RAPID" AND UniqueIPs > 1 | RiskScore := 90;
    DetectionTier = "RAPID" | RiskScore := 80;
    DetectionTier = "STANDARD" AND UniqueIPs > 2 | RiskScore := 70;
    DetectionTier = "STANDARD" | RiskScore := 60;
    DetectionTier = "SUSTAINED" AND UniqueApps > 2 | RiskScore := 55;
    * | RiskScore := 50;
  }
```

**Output Fields**:
- `user.name`, `user.full_name` - Target account
- `DetectionTier` - RAPID/STANDARD/SUSTAINED
- `RiskScore` - Composite risk (90/80/70/60/55/50)
- `MinutesSinceLastAttempt` - Recency indicator
- `TotalFailures` - Total failed attempts in window
- `Failures_15m` - Estimated failures in 15-minute window
- `Failures_30m` - Estimated failures in 30-minute window
- `AttackVelocity` - Failures per minute
- `UniqueIPs`, `UniqueDevices`, `UniqueApps` - Attack diversity metrics
- `AttackPattern` - Attack classification
- `FirstAttemptFormatted`, `LastAttemptFormatted` - Temporal context
- `DurationFormatted` - Attack duration
- `IsSaseNetwork` - VPN context

**Why This Works**:

This detection demonstrates **multi-dimensional threat detection**:

1. **Temporal Intelligence**: Three detection windows catch different attack patterns
   - Fast attacks (RAPID): Caught in 15 minutes
   - Standard attacks (STANDARD): Caught in 30 minutes
   - Slow attacks (SUSTAINED): Caught in 1 hour

2. **Duplicate Prevention**: Temporal gating ensures each attack generates ONE alert
   - Extended lookback (1h10m) provides full context
   - Short alert window (20m) prevents duplicate processing
   - Result: 4x faster detection (15m schedule) with zero duplicates

3. **CQL Arithmetic Workaround**: Pre-calculation pattern
   - **Problem**: CQL case statements don't support arithmetic expressions
   - **Solution**: Calculate values BEFORE case statement, reference in conditions
   - Pattern reusable for any detection needing computed comparisons

4. **Attack Pattern Recognition**: Context enrichment aids investigation
   - "Distributed" attack → Multiple compromised machines or botnet
   - "High-Velocity" attack → Automated tool (hydra, burp)
   - "Multi-Application" spray → Account enumeration

**Tuning Decision Matrix**:

| Environment | RAPID | STANDARD | SUSTAINED | Schedule | Notes |
|-------------|-------|----------|-----------|----------|-------|
| Small org (<500 users) | 3/15m | 5/30m | 8/1h | @every 15m | Default config |
| Medium org (500-2000) | 4/15m | 6/30m | 10/1h | @every 15m | Slightly higher thresholds |
| Large org (2000+) | 5/15m | 8/30m | 12/1h | @every 15m | Higher baseline auth failures |
| High security | 2/15m | 4/30m | 6/1h | @every 5m | Ultra-fast detection |
| Low noise tolerance | 5/15m | 8/30m | 12/1h | @every 30m | Reduce alert volume |

**Tuning Considerations**:
- **Alert window calculation**: Always `schedule + 5-10m grace period`
- **Threshold adjustment**: Increase RAPID threshold if too many alerts, decrease for faster detection
- **Schedule optimization**: Faster schedule (5m) requires shorter alert window (10m)
- **False positive reduction**: Add trusted user/IP/app exclusions BEFORE groupBy
- **Risk score tuning**: Adjust multipliers based on organization's threat model

---

### Example 4: Microsoft EntraID - Unauthorized International Sign-in

**File**: `resources/detections/microsoft/microsoft_entraid_unauthorized_international_signin.yaml`

**Purpose**: Detect successful international sign-ins from users not authorized for international travel. Dynamically adjusts severity based on destination country's risk level and user's privilege level, helping identify potential unauthorized access from foreign locations or compromised accounts.

**Status**: Inactive (group checking not working currently - needs EntraID group API integration)

**Tuning Techniques Applied**:

1. **Geographic Risk Classification (4 Tiers)**
   - Critical: CN, RU, KP, IR, SY, CU (100 points)
   - High: VN, RO, UA, BY, VE, NG, PK (75 points)
   - Low: GB, DE, FR, AU, JP, NZ, CH, SE, NO, DK, NL, BE (25 points)
   - Medium: All others (50 points)

2. **Privilege-Based Risk Multipliers**
   - Global admin + non-low risk: +25 points
   - Security admin + non-low risk: +20 points
   - Engineering AWS + non-low risk: +15 points
   - Standard users: No multiplier

3. **Composite Risk Scoring**
   - Base score: Country risk (25-100)
   - Escalation: Privilege multiplier (0-25)
   - Final score determines alert severity

4. **Using $entraid_check_privileged_groups()**
   - Checks user membership in EntraID groups
   - Identifies privilege categories (global_admin, security_admin, etc.)
   - Filters users with `HasInternationalAccess=false`

5. **Actionable Response Recommendations**
   - Critical + privileged: "IMMEDIATE: Disable account, reset credentials"
   - Critical + standard: "HIGH PRIORITY: Contact user immediately, verify travel"
   - High + privileged: "URGENT: Verify with user, review recent activity"
   - Medium/Low: "Contact user, add to International Travel group if legitimate"

**Complete CQL Query**:

```cql
#Vendor="microsoft" #event.dataset=/entraid\.signin/ #repo!="xdr*"
| array:contains(array="event.category[]", value="authentication")
| #event.outcome=success

// Get location information
| ipLocation(source.ip)

// CONFIGURATION: Countries that don't require International Travel authorization
// Typically includes home country and trusted neighboring countries
// Check if sign-in is from a country requiring authorization
| !in(field="source.ip.country", values=["US", "CA", "MX"])

// Extract user identity for group checking
| $entraid_enrich_user_identity()

// Check privileged group memberships including International Travel
| $entraid_check_privileged_groups(strict_mode="false", include_aws_groups="false")

// Alert only if user is NOT in International Travel group
| HasInternationalAccess=false

// ============================================
// RISK SCORING - Geographic classification
// ============================================

// Risk scoring based on destination country
| case {
    in(field="source.ip.country", values=["CN", "RU", "KP", "IR", "SY", "CU"]) | CountryRisk := "critical";
    in(field="source.ip.country", values=["VN", "RO", "UA", "BY", "VE", "NG", "PK"]) | CountryRisk := "high";
    in(field="source.ip.country", values=["GB", "DE", "FR", "AU", "JP", "NZ", "CH", "SE", "NO", "DK", "NL", "BE"]) | CountryRisk := "low";
    * | CountryRisk := "medium";
  }

// Set country risk score
| case {
    CountryRisk="critical" | CountryRiskScore := 100;
    CountryRisk="high" | CountryRiskScore := 75;
    CountryRisk="medium" | CountryRiskScore := 50;
    CountryRisk="low" | CountryRiskScore := 25;
    * | CountryRiskScore := 50;
  }

// Calculate composite risk score
| CompositeRiskScore := CountryRiskScore

// ============================================
// PRIVILEGE ESCALATION - Add risk for privileged users
// ============================================

// Add risk for privileged users accessing from risky locations
| case {
    PrivilegeCategory="global_admin" AND CountryRisk!="low" | CompositeRiskScore := CompositeRiskScore + 25;
    PrivilegeCategory="security_admin" AND CountryRisk!="low" | CompositeRiskScore := CompositeRiskScore + 20;
    PrivilegeCategory="engineering_aws" AND CountryRisk!="low" | CompositeRiskScore := CompositeRiskScore + 15;
    * ;
  }

// ============================================
// SEVERITY DETERMINATION - Composite scoring
// ============================================

// Determine alert severity based on composite risk
| case {
    CompositeRiskScore >= 100 | AlertSeverity := "critical";
    CompositeRiskScore >= 75 | AlertSeverity := "high";
    CompositeRiskScore >= 50 | AlertSeverity := "medium";
    * | AlertSeverity := "low";
  }

// ============================================
// RESPONSE RECOMMENDATIONS - Actionable guidance
// ============================================

// Build detailed alert information
| AlertTitle := format("Unauthorized International Sign-in: %s from %s",
    field=[UserEmail, source.ip.country])

| AlertDescription := format(
    "User %s (Privilege: %s) successfully authenticated from %s (%s, %s) without International Travel authorization. Country Risk: %s, User has %d group memberships.",
    field=[UserEmail, PrivilegeCategory, source.ip.country, source.ip.city, source.ip, CountryRisk, group_count]
  )

// Response recommendations based on risk
| case {
    CountryRisk="critical" AND IsPrivilegedUser=true | RecommendedAction := "IMMEDIATE: Disable account, reset credentials, investigate all recent activity";
    CountryRisk="critical" | RecommendedAction := "HIGH PRIORITY: Contact user immediately, verify travel, consider account suspension";
    CountryRisk="high" AND IsPrivilegedUser=true | RecommendedAction := "URGENT: Verify with user, review recent account activity, consider MFA reset";
    CountryRisk="high" | RecommendedAction := "Contact user to verify travel, add to International Travel group if legitimate";
    * | RecommendedAction := "Verify with user, add to International Travel group if legitimate business travel";
  }

// Investigation context
| case {
    AlertSeverity="critical" | RequiresInvestigation := true;
    AlertSeverity="high" AND PrivilegeLevelScore >= 3 | RequiresInvestigation := true;
    CountryRisk="critical" | RequiresInvestigation := true;
    * | RequiresInvestigation := false;
  }

// Include all relevant fields for investigation and response
| select([
    @timestamp,
    AlertSeverity,
    AlertTitle,
    RequiresInvestigation,
    UserEmail,
    UserIdentifier,
    PrivilegeCategory,
    highest_privilege_tier,
    HasInternationalAccess,
    group_count,
    source.ip,
    source.ip.country,
    source.ip.city,
    CountryRisk,
    CountryRiskScore,
    CompositeRiskScore,
    RecommendedAction,
    AlertDescription,
    event.action,
    Vendor.userPrincipalName,
    Vendor.deviceDetail.browser,
    Vendor.deviceDetail.operatingSystem,
    Vendor.deviceDetail.deviceId,
    Vendor.clientAppUsed,
    MitreTactic,
    MitreTechnique
  ])
```

**Risk Score Calculation Breakdown**:

| Scenario | Country Risk | Privilege Multiplier | Composite Score | Alert Severity |
|----------|--------------|----------------------|-----------------|----------------|
| Standard user → China | 100 | 0 | 100 | Critical |
| Global admin → China | 100 | +25 | 125 | Critical |
| Standard user → Vietnam | 75 | 0 | 75 | High |
| Security admin → Vietnam | 75 | +20 | 95 | High |
| Standard user → France | 25 | 0 | 25 | Low |
| Global admin → France | 25 | 0 | 25 | Low (no escalation for low-risk countries) |
| Engineering AWS → Ukraine | 75 | +15 | 90 | High |
| Standard user → Brazil | 50 | 0 | 50 | Medium |

**Output Fields**:
- `AlertSeverity` - critical/high/medium/low
- `AlertTitle` - Formatted alert title
- `RequiresInvestigation` - Boolean flag for SOC prioritization
- `UserEmail`, `UserIdentifier` - User context
- `PrivilegeCategory` - global_admin/security_admin/engineering_aws/standard
- `highest_privilege_tier` - Numeric privilege level
- `HasInternationalAccess` - International Travel group membership
- `group_count` - Total EntraID group memberships
- `source.ip`, `source.ip.country`, `source.ip.city` - Geographic context
- `CountryRisk` - critical/high/medium/low
- `CountryRiskScore` - Numeric base risk (25-100)
- `CompositeRiskScore` - Final risk score with privilege multiplier
- `RecommendedAction` - Actionable response guidance
- `AlertDescription` - Detailed alert context
- Device and browser context from EntraID

**Why This Works**:

This detection demonstrates **contextual risk scoring** - combining multiple signals for accurate threat assessment:

1. **Geographic Intelligence**: Not all international access is equal
   - Critical countries (adversary nations): High baseline risk
   - Low-risk countries (allies): Lower baseline risk, still requires authorization
   - Country lists tunable based on organization's geopolitical threat model

2. **Privilege-Aware Detection**: Admin accounts warrant higher scrutiny
   - Global admin from China: 125 points (Critical)
   - Standard user from China: 100 points (Critical, but different response)
   - Admin from France: 25 points (Low - travel likely, but verify)

3. **Actionable Recommendations**: SOC knows exactly what to do
   - No generic "investigate suspicious activity"
   - Specific actions based on risk level
   - Time urgency clearly indicated (IMMEDIATE vs URGENT vs standard)

4. **Business Logic Integration**: `HasInternationalAccess=false`
   - Leverages existing organizational process (International Travel group)
   - Zero false positives for authorized travelers
   - Automatic alert suppression when user added to group

**Tuning Considerations**:
- **Country lists**: Customize based on organization's global presence and threat model
- **Privilege categories**: Add/modify based on EntraID role structure
- **Risk multipliers**: Adjust +25/+20/+15 values based on risk tolerance
- **Home countries**: Update `["US", "CA", "MX"]` to reflect organization's locations
- **Response actions**: Customize recommendations to match IR playbooks
- **Group checking**: Requires EntraID API integration for group membership lookups

---

### Example 5: Anomalous USB Exfiltration (Statistical Baseline - Teaching Example)

**File**: `resources/detections/generic/anomolous_usb_exfiltration.yaml`

**Status**: Inactive but excellent teaching example for statistical baseline patterns

**Purpose**: Identify potential data exfiltration via USB devices by establishing statistical baselines of normal file transfer activity for each user and endpoint. Analyzes both file count and data volume transferred to USB devices, generating alerts when either metric significantly exceeds normal behavior using avg + 3*stddev thresholds.

**Tuning Techniques Applied**:

1. **defineTable() with 30-Day Historical Baseline**
   - Analyzes last 30 days excluding current + previous hour
   - Per-user + per-endpoint baselines (personalized)
   - Calculates mean and standard deviation for both file count and data volume

2. **2-Hour Exclusion Window**
   - `start=30d, end=1h` excludes current hour
   - Prevents current events from contaminating baseline
   - Matches with 1-hour detection schedule

3. **Dynamic Threshold Calculation**
   - `files_threshold := avg_files_written + 3 * std_dev_files_written`
   - `bytes_threshold := avg_bytes_written + 3 * std_dev_bytes_written`
   - 3-sigma threshold = 99.7% confidence (highly anomalous)

4. **Anomaly Ratio Output**
   - Calculates "X times above normal" for both metrics
   - Provides context: "2.5x files, 10.3x bytes above normal"
   - Helps SOC assess severity

5. **Rich Data Formatting**
   - Automatic TB/GB/MB/KB conversion
   - Formatted output: "45.3 GB" instead of "48629514240"
   - Includes file list for investigation

6. **Device Context Enrichment**
   - Tracks both Windows (USB) and Mac (removable disk) devices
   - Filters system files (Spotlight indexes)
   - Per-endpoint + per-user correlation

**Complete CQL Query with Detailed Comments**:

```cql
// ============================================================
// USB Anomaly Detection - Statistical Baseline Comparison
// ============================================================

// Step 1: Define baseline table with historical USB file activity
// (last 30 days excluding the last hour)
defineTable(
    name="usb_write_baseline",
    start=30d,
    end=1h,
    query={
        // Get FileWritten events for files written to USB drives on Windows and Mac
        #event_simpleName=/FileWritten$/ AND
        ((event_platform=Win DiskParentDeviceInstanceId="USB*") OR
        (event_platform=Mac IsOnRemovableDisk=1)) AND
        TargetFileName!="*.Spotlight-V100*"

        // Create hourly time buckets and group by endpoint/user
        | time_bucket := formatTime("%Y-%m-%d %H", field=@timestamp)
        | groupBy([time_bucket, aid, ComputerName, UserName],
            function=[
                count(TargetFileName, as=files_written_count),
                sum(Size, as=total_bytes_written)
            ],
            limit=max)

        // Calculate baseline statistics per endpoint/user combination
        | groupBy([aid, ComputerName, UserName],
            function=[
                avg(files_written_count, as=avg_files_written),
                stdDev(files_written_count, as=std_dev_files_written),
                avg(total_bytes_written, as=avg_bytes_written),
                stdDev(total_bytes_written, as=std_dev_bytes_written)
            ],
            limit=max
        )
    },
    include=[*]
)

// Step 2: Query current USB file writing activity
| #event_simpleName=/FileWritten$/ AND
  ((event_platform=Win DiskParentDeviceInstanceId="USB*") OR
  (event_platform=Mac IsOnRemovableDisk=1)) AND
  TargetFileName!="*.Spotlight-V100*"

// Step 3: Create hourly time buckets for current activity
| time_bucket := formatTime("%Y-%m-%d %H", field=@timestamp)

// Step 4: Group current activity by endpoint, user, and time bucket
| groupBy([time_bucket, aid, ComputerName, UserName],
    function=[
        count(TargetFileName, as=files_written_count),
        sum(Size, as=total_bytes_written),
        collect([TargetFileName])
    ],
    limit=max)

// Step 5: Match against the historical baseline
| match(table="usb_write_baseline", field=[aid, ComputerName, UserName], strict=false)

// Step 6: Calculate dynamic thresholds (avg + 3 standard deviations)
| files_threshold := avg_files_written + 3 * std_dev_files_written
| bytes_threshold := avg_bytes_written + 3 * std_dev_bytes_written

// Step 7: Set default thresholds for endpoints with no baseline data
// Note: If no baseline exists (no match), avg fields will be null
| default(field=files_threshold, value=50)
| default(field=bytes_threshold, value=104857600)  // 100 MB in bytes

// Step 8: Create alert reason based on threshold violations
| case {
    test(files_written_count > files_threshold) |
        case {
            test(total_bytes_written > bytes_threshold) |
                alert_reason := "Both file count and data volume exceeded";
            * | alert_reason := "File count exceeded";
        };
    test(total_bytes_written > bytes_threshold) |
        alert_reason := "Data volume exceeded";
    * | alert_reason := "No threshold exceeded";
}

// Step 9: Filter to only anomalous events
| alert_reason != "No threshold exceeded"

// Step 10: Format data volume for readability
| case {
    test(total_bytes_written>=1099511627776) |
        readable_size := unit:convert(total_bytes_written, to=T) |
        format("%,.2f TB", field=["readable_size"], as="readable_size");
    test(total_bytes_written>=1073741824) |
        readable_size := unit:convert(total_bytes_written, to=G) |
        format("%,.2f GB", field=["readable_size"], as="readable_size");
    test(total_bytes_written>=1048576) |
        readable_size := unit:convert(total_bytes_written, to=M) |
        format("%,.2f MB", field=["readable_size"], as="readable_size");
    test(total_bytes_written>=1024) |
        readable_size := unit:convert(total_bytes_written, to=k) |
        format("%,.2f KB", field=["readable_size"], as="readable_size");
    * |
        readable_size := format("%,.0f Bytes", field=["total_bytes_written"]);
}

// Step 11: Calculate anomaly ratios (how much above normal)
| case {
    test(avg_files_written>0) | files_excess_ratio := files_written_count / avg_files_written;
    * | files_excess_ratio := files_written_count;
}

| case {
    test(avg_bytes_written>0) | bytes_excess_ratio := total_bytes_written / avg_bytes_written;
    * | bytes_excess_ratio := total_bytes_written;
}

// Step 12: Create summary of anomaly severity
| anomaly_summary := format("%.1fx files, %.1fx bytes above normal",
                          field=["files_excess_ratio", "bytes_excess_ratio"])

// Step 13: Format output for analysis
| table([
    time_bucket,
    ComputerName,
    UserName,
    files_written_count,
    readable_size,
    alert_reason,
    anomaly_summary,
    TargetFileName
], limit=1000)

// Step 14: Sort by most anomalous activity first
| sort(files_excess_ratio, order=desc)
```

**Statistical Baseline Explanation**:

1. **Why 30 Days?**
   - Balances stability (enough data) with recency (reflects current patterns)
   - Captures weekly cycles (Mon-Fri work patterns, weekend activity)
   - Adapts to user role changes over time

2. **Why 3 Standard Deviations?**
   - 68% of data within 1σ (too many false positives)
   - 95% of data within 2σ (some false positives)
   - 99.7% of data within 3σ (highly anomalous, rare false positives)
   - Formula: `threshold = mean + 3 * stddev`

3. **Why Per-User + Per-Endpoint Baselines?**
   - Different users have different normal patterns
   - Developer with daily USB backups: High baseline (no alerts on normal behavior)
   - Executive who never uses USB: Low baseline (alerts on any USB usage)
   - Result: Personalized thresholds eliminate false positives

4. **Example Calculations**:
   ```
   User: John (Developer)
   Baseline (30 days):
     - avg_files_written = 20
     - std_dev_files_written = 5
     - Threshold = 20 + (3 * 5) = 35 files

   Current hour: 40 files → ALERT (15% above threshold)

   User: Sarah (Executive)
   Baseline (30 days):
     - avg_files_written = 0
     - std_dev_files_written = 0
     - Threshold = 0 + (3 * 0) = 0 → default(50) applied

   Current hour: 55 files → ALERT (first-time USB usage)
   ```

**Output Fields**:
- `time_bucket` - Hour of anomalous activity
- `ComputerName` - Endpoint
- `UserName` - User account
- `files_written_count` - Number of files written to USB
- `readable_size` - Formatted data volume (e.g., "45.3 GB")
- `alert_reason` - "Both exceeded", "File count exceeded", or "Data volume exceeded"
- `anomaly_summary` - "2.5x files, 10.3x bytes above normal"
- `TargetFileName` - List of files written (for investigation)

**Why This Pattern Works**:

Statistical baselines solve the **"one size fits all" problem**:

**Traditional Approach**:
```
Alert on: >100 files OR >1 GB per hour
Problems:
- Developer with daily USB backups: Constant false positives
- Executive using USB for first time: Missed detection (under threshold)
- No context on severity (110 files = minor, 1000 files = major)
```

**Baseline Approach**:
```
Alert on: deviation from 30-day normal behavior
Benefits:
- Developer baseline: 150 files normal → alert on 200+ files
- Executive baseline: 0 files normal → alert on ANY USB usage
- Anomaly ratio provides severity: "2.5x normal" vs "10x normal"
- Automatic adaptation: No manual threshold tuning required
```

**When to Use This Pattern**:

Statistical baselines are ideal for:
- **Volume-based detections**: File transfers, API calls, data access
- **User behavior monitoring**: Login patterns, command execution, network connections
- **Resource usage**: Compute, storage, network bandwidth
- **Temporal patterns**: Night/weekend activity, unusual timing

**NOT ideal for**:
- **One-time critical events**: Root login, security group changes (every occurrence matters)
- **Binary detections**: Malware execution, forbidden commands (threshold = 1)
- **New environments**: Requires historical data (30-day minimum)

**Tuning Considerations**:
- **Baseline window**: 30d (stable), 14d (responsive), 7d (highly adaptive)
- **Exclusion window**: Match schedule + ingestion delay (1h schedule = 1h exclusion)
- **Sigma threshold**: 3σ (rare events), 2σ (moderate sensitivity), 4σ (extremely rare)
- **Default thresholds**: Set based on "reasonable worst-case" for new users/endpoints
- **Aggregation granularity**: Hourly (current), 15-minute (faster detection), 4-hour (broader patterns)

---

## Well-Tuned Detection Examples

### Simple Threshold Tuning: AWS Brute Force Detection

**File**: `resources/detections/aws/aws___cloudtrail___potential_brute_force_attack_on_iam_users_via_aws_management_console.yaml`

**Key Patterns**:
- Multi-threshold OR logic: `failed_logins>=50 OR distinct_users>=10`
- IP enrichment: `asn(source.ip)` and `ipLocation(source.ip)`
- Aggregation with multiple metrics
- Collect for investigation context

```cql
| asn(source.ip)
| ipLocation(source.ip)
| groupBy([cloud.account.id, event.action, event.reason],
    function=[
        distinct_users := count(user.name, distinct=true),
        failed_logins := count(),
        collect([user.name, source.ip.org, source.ip.country, source.ip.city])
    ])
| failed_logins>=50 OR distinct_users>=10
```

**Tuning Applied**:
- High threshold (50 failures) for volume-based detection
- Account spray detection (10+ distinct users)
- IP context collection for investigation

---

### macOS Platform SSO Detection (Risk Scoring)

**File**: `resources/detections/microsoft/microsoft_entra_id_macos_platform_sso_token_failure.yaml`

**Key Patterns**:
- Configurable risk threshold: `MinimumRiskScore := 70`
- Multi-level severity with case statements
- Actionable recommendations in output
- Comprehensive alert formatting

```cql
// Configurable detection threshold
| MinimumRiskScore := 70

// Risk scoring based on failure count
| case {
    test(_totalFailures >= 10) | _severity := "Critical" | _riskScore := 90 ;
    test(_totalFailures >= 5) | _severity := "High" | _riskScore := 70 ;
    test(_totalFailures >= 3) | _severity := "Medium" | _riskScore := 50 ;
    * | _severity := "Low" | _riskScore := 30 ;
}

// Filter to configured threshold
| test(_riskScore >= MinimumRiskScore)
```

**Tuning Applied**:
- Configurable risk threshold (default High+Critical)
- Dynamic severity based on failure count
- Root cause analysis and recommendations
- Structured output for analyst workflow

---

### AWS Root Console Login (Critical Alert)

**File**: `resources/detections/aws/aws___cloudtrail___console_root_login.yaml`

**Key Patterns**:
- Simple, focused query for critical events
- No threshold needed - every occurrence matters
- High severity (90)

**When to Use This Pattern**:
- Root account activity
- Production environment changes
- Security control modifications

---

### AWS Session Hijacking (Geo-Based Detection)

**File**: `resources/detections/aws/aws___cloudtrail___potential_session_hijacking.yaml`

**Key Patterns**:
- Geographic anomaly detection
- Session correlation
- IP context enrichment

---

## Detection Structure Patterns

### OOTB Template (Before Tuning)

```yaml
name: Detection Name
rule_id: uuid-from-crowdstrike
description: |
  Basic description from vendor
severity: 50
status: active
tactic: TA00XX
technique: T1XXX
search:
  filter: |
    #repo=cloudtrail
    // Basic query without enrichment
    | event.action="SomeAction"
    | count() >= 5  # Low threshold
  lookback: 1h0m
  trigger_mode: summary
  outcome: detection
operation:
  schedule:
    definition: '@every 1h0m'
```

### Tuned Template (After Enhancement)

```yaml
name: Detection Name - Tuned
resource_id: vendor_detection_name_tuned
description: |
  Enhanced description with context

  Tuning Applied:
  - Service account exclusion via $aws_classify_identity_type
  - Trusted network filtering via $trusted_network_detector
  - Threshold adjusted from 5 to 50 for 500-user environment
  - Added geo-risk scoring

severity: 50
status: active
tactic: TA00XX
technique: T1XXX
search:
  filter: |
    #repo=cloudtrail
    #Vendor=aws

    // Identity enrichment pipeline
    | $aws_enrich_user_identity()
    | $aws_classify_identity_type(include_service_detection="true")

    // Network validation
    | $trusted_network_detector(extend_trust="true")

    // Geographic risk
    | $score_geo_risk()

    // Core filters
    | IsHumanIdentity=true
    | IsExcluded=false

    // Detection logic
    | event.action="SomeAction"

    // Aggregation
    | groupBy([UserIdentity, source.ip],
        function=[
            count := count(),
            events := collect([event.action]),
            first_seen := min(@timestamp),
            last_seen := max(@timestamp)
        ])

    // Environment-appropriate threshold
    | count >= 50

    // Final filter with geo context
    | FinalShouldAlert=true

    // Output fields for investigation
    | select([
        @timestamp,
        UserIdentity,
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

---

## Detections Using Enrichment Functions

These detections demonstrate proper use of the saved search functions for filtering and enrichment.

### Using $trusted_network_detector()

**File**: `resources/detections/aws/aws_cloudtrail_management_console_login_from_multiple_ip_addresses.yaml`

```cql
| ipLocation(source.ip)
| asn(source.ip)
| $trusted_network_detector()
| IsExcluded=false  // Filter to only non-SASE sources
| groupBy([event.action, Vendor.userIdentity.arn],
    function=[
        count(source.ip, distinct=true, as=distinct_ip_count),
        collect([source.ip, source.ip.country, source.ip.city])
    ])
| distinct_ip_count>=2
```

**Key Pattern**: Filter out SASE VPN traffic before detecting multiple IP logins.

---

### Using $aws_service_account_detector() + $aws_trusted_ip_detector()

**File**: `resources/detections/aws/aws_cloudtrail_unusual_cross_account_trust_relationship_activity.yaml`

```cql
| $aws_service_account_detector(strict_mode="true", include_temp="false")
| IsServiceAccount=false
| $aws_trusted_ip_detector(strict_mode="false", include_private="true")

// Look for first-seen patterns (baseline comparison)
| NOT match(
    file="baseline_access_patterns",
    field=[Vendor.userIdentity.type, Vendor.userIdentity.arn, Vendor.requestParameters.roleArn]
)

// Network context
| asn(source.address)
| ipLocation(source.address)
```

**Key Pattern**: Exclude service accounts AND trusted IPs, then use baseline comparison.

---

### All Detections Using Functions (42 total)

**Function Usage Breakdown**:
- AWS functions: 32 detections
- Network trust functions: 8 detections
- EntraID functions: 1 detection (more coming as group API integration completes)
- GitHub functions: 1 detection

**Key files by function category**:

**AWS Identity Functions**:
- `$aws_enrich_user_identity()` - Normalizes AWS identity fields
- `$aws_classify_identity_type()` - Classifies as human/service/temporary
- `$aws_service_account_detector()` - Service account detection with confidence levels

Example files:
- `aws_cloudtrail_management_console_login_from_multiple_ip_addresses.yaml`
- `aws_cloudtrail_unusual_cross_account_trust_relationship_activity.yaml`
- `aws_cloudtrail_successful_single_factor_authentication.yaml`
- `aws_cloudtrail_anomalous_access_key_authentication_pattern.yaml`
- `aws_cloudtrail_kms_anomalous_data_key_generation.yaml`

**Network Trust Functions**:
- `$trusted_network_detector()` - Identifies SASE VPN and trusted networks
- `$aws_trusted_ip_detector()` - AWS-specific trusted IP validation
- `$sase_validate_connection_source()` - SASE VPN validation with exit node context

Example files:
- Most AWS CloudTrail detections (filters VPN traffic)
- `microsoft_entra_id_multiple_failed_login_attempts_by_single_user.yaml`
- `microsoft_entra_id_multiple_failed_login_optimized.yaml`

**GitHub Functions**:
- `$github_service_account_detector()` - Identifies GitHub Apps, bots, and service accounts

Example files:
- `github___multiple_branch_deletions.yaml`

**EntraID Functions**:
- `$entraid_enrich_user_identity()` - Normalizes EntraID identity fields
- `$entraid_classify_user_type()` - Classifies as user/service/guest
- `$entraid_check_privileged_groups()` - Checks privilege levels and group memberships
- `$entraid_lookup_trust_level()` - Assigns trust levels based on patterns

Example files:
- `microsoft_entraid_unauthorized_international_signin.yaml`

**Geographic Risk Functions**:
- `$score_geo_risk()` - Assigns risk scores based on country, ISP, and VPN context

**Baseline Functions**:
- `defineTable()` - Statistical baseline comparison pattern

Example files:
- `aws_cloudtrail_kms_anomalous_data_key_generation.yaml`
- `anomolous_usb_exfiltration.yaml`

---

## Saved Search Function Examples

### AWS Identity Enrichment Pipeline

**Files**:
- `resources/saved_searches/aws_enrich_user_identity.yaml`
- `resources/saved_searches/aws_classify_identity_type.yaml`
- `resources/saved_searches/aws_service_account_detector.yaml`

**Usage Pattern**:
```cql
// Full AWS identity enrichment
| $aws_enrich_user_identity()
| $aws_classify_identity_type(include_service_detection="true")
| IsHumanIdentity=true
```

---

### Network Trust Validation

**Files**:
- `resources/saved_searches/trusted_network_detector.yaml`
- `resources/saved_searches/sase_validate_connection_source.yaml`

**Usage Pattern**:
```cql
// Filter SASE VPN and trusted networks
| $trusted_network_detector(extend_trust="true", include_private="true")
| IsExcluded=false
```

---

### Geographic Risk Scoring

**Files**:
- `resources/saved_searches/score_geo_risk.yaml`
- `resources/saved_searches/sase_validate_connection_source.yaml`

**Usage Pattern**:
```cql
// Full geo-risk with VPN context
| $sase_validate_connection_source()
| $score_geo_risk()
| FinalShouldAlert=true
```

---

### Cross-Account Trust Validation

**File**: `resources/saved_searches/aws_validate_cross_account_trust.yaml`

**Usage Pattern**:
```cql
// Detect untrusted cross-account access
| $aws_validate_cross_account_trust()
| CrossAccountRisk=~in(values=["critical", "high"])
```

---

### EntraID Identity Pipeline

**Files**:
- `resources/saved_searches/entraid_enrich_user_identity.yaml`
- `resources/saved_searches/entraid_classify_user_type.yaml`
- `resources/saved_searches/entraid_lookup_trust_level.yaml`
- `resources/saved_searches/entraid_check_privileged_groups.yaml`

**Usage Pattern**:
```cql
// Full EntraID enrichment
| $entraid_enrich_user_identity()
| $entraid_classify_user_type()
| UserType="user_account"

// With privilege checking
| $entraid_check_privileged_groups(strict_mode="false", include_aws_groups="false")
| IsPrivilegedUser=true
```

---

### GitHub Service Account Detection

**File**: `resources/saved_searches/github_service_account_detector.yaml`

**Usage Pattern**:
```cql
// Detect GitHub service accounts
| $github_service_account_detector()
| ServiceAccountType!="merge-queue"  // Exclude only specific bot types
```

---

## Browse More Examples

### AWS Detections
```bash
ls resources/detections/aws/
```

Key examples:
- `aws___cloudtrail___console_root_login.yaml` - Critical alert, no threshold
- `aws___cloudtrail___potential_brute_force_*.yaml` - Threshold tuning
- `aws___cloudtrail___potential_session_hijacking.yaml` - Geo-based
- `aws___cloudtrail___iam_administratoraccess_policy_attached_*.yaml` - Privilege escalation
- `aws_cloudtrail_kms_anomalous_data_key_generation.yaml` - Statistical baseline

### Microsoft/EntraID Detections
```bash
ls resources/detections/microsoft/
```

Key examples:
- `microsoft_entra_id_macos_platform_sso_token_failure.yaml` - Risk scoring pattern
- `microsoft_entra_id_multiple_failed_login_optimized.yaml` - Multi-tier severity, temporal gating
- `microsoft_entraid_unauthorized_international_signin.yaml` - Geographic intelligence, privilege-aware risk
- Microsoft M365/SharePoint detections - Data exfiltration patterns

### GitHub Detections
```bash
ls resources/detections/github/
```

Key examples:
- `github___multiple_branch_deletions.yaml` - Service account filtering
- `github___force_push_to_protected_branch.yaml` - Repository security
- `github___protected_branch_deleted.yaml` - Critical security control

### Generic Detections
```bash
ls resources/detections/generic/
```

Key examples:
- `anomolous_usb_exfiltration.yaml` - Statistical baseline pattern (teaching example)

### Saved Search Functions
```bash
ls resources/saved_searches/
```

All 19+ functions available for enrichment and filtering.

---

## Quick Reference: Which Example to Use

| Detection Type | Reference Example | Key Technique |
|----------------|-------------------|---------------|
| Service account filtering | `github___multiple_branch_deletions.yaml` | Contextual exclusions |
| Statistical baseline | `aws_cloudtrail_kms_anomalous_data_key_generation.yaml` | defineTable() pattern |
| Multi-tier severity | `microsoft_entra_id_multiple_failed_login_optimized.yaml` | Temporal gating, velocity analysis |
| Geographic intelligence | `microsoft_entraid_unauthorized_international_signin.yaml` | Privilege-aware risk |
| Brute force/credential attack | `aws___cloudtrail___potential_brute_force_attack_*.yaml` | Multi-threshold OR logic |
| Root/admin account activity | `aws___cloudtrail___console_root_login.yaml` | Zero-threshold critical alert |
| SSO/authentication issues | `microsoft_entra_id_macos_platform_sso_token_failure.yaml` | Risk scoring |
| Cross-account access | Use `$aws_validate_cross_account_trust()` | Trust validation |
| USB exfiltration | `anomolous_usb_exfiltration.yaml` | Statistical baseline (teaching) |
| Network filtering | Use `$trusted_network_detector()` | VPN/trusted network exclusion |

---

## Pattern Summary

### When to Use Each Pattern

**Service Account Filtering**:
- Use when: Automation creates high volumes of events
- Example: GitHub branch deletions, AWS API calls
- Key: Contextual exclusions (not blanket filtering)

**Statistical Baselines**:
- Use when: Volume-based detections, user behavior monitoring
- Example: KMS key generation, USB transfers, API calls
- Key: 30-day baseline, 3-sigma threshold, per-user baselines

**Multi-Tier Severity**:
- Use when: Different attack patterns warrant different response urgency
- Example: Brute force (RAPID/STANDARD/SUSTAINED)
- Key: Multiple time windows, temporal gating, velocity analysis

**Geographic Intelligence**:
- Use when: Location context matters for risk assessment
- Example: International sign-ins, unusual IP access
- Key: Country risk tiers, privilege-aware escalation

**Risk Scoring**:
- Use when: Multiple factors determine severity
- Example: Failed authentication (count + velocity + diversity)
- Key: Composite scoring, escalation multipliers

**Zero-Threshold Critical**:
- Use when: Every occurrence requires investigation
- Example: Root account usage, security control changes
- Key: No aggregation, immediate alerting

---

## Additional Resources

See also:
- `DETECTION-ENGINEERING-WORKFLOW.md` - Full detection engineering process
- `INSTRUCTIONS.md` - Detection tuning methodology
- `PATTERNS.md` - Detection pattern library
- `FUNCTIONS.md` - Saved search function reference
