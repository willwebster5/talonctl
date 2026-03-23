# Production-Ready Query Examples

Complete, tested queries from deployed security detections. All examples are from real-world SOC operations.

## Example 1: Statistical Anomaly Detection with Baseline

**Purpose**: Detect unusual spikes in AWS CloudTrail management activity by comparing against a 7-day baseline using statistical thresholds.

**Source**: `resources/detections/aws/aws_-_cloudtrail_-_management_activity_spike_in_a_short_period_of_time.yaml`

**Key Techniques**:
- `defineTable()` for historical baselining
- Statistical thresholds (mean + 3× standard deviation)
- Time bucketing with `formatTime()`
- Exclusion lists with negative regex
- Handling identities with no baseline activity

```cql
defineTable(
name="mgmt_events_stats",
start=7d,
end=1h,
query={
    (#repo="cloudtrail" OR #repo="fcs_csp_events") #Vendor="aws" #event.module="cloudtrail"
    | #event.kind="event" #event.outcome="success"
    | event.action=/^(?:Delete|Put|Create|Update|Attach|Detach|Run|Terminate|Modify|Authorize|Revoke|Restore|Schedule|Enable|Disable|InviteAccountToOrganization|AssumeRole)/
    | time_bucket := formatTime("%Y-%m-%d %H", field=@timestamp)
    | groupBy([time_bucket,Vendor.userIdentity.arn],function=count(as=mgmt_events_total_count), limit=max)
    | groupBy(Vendor.userIdentity.arn,
        function=[
            mgmt_events_average_count := avg(mgmt_events_total_count),
            mgmt_events_std_deviation_count := stdDev(mgmt_events_total_count)
        ],
        limit=max
    )
},
include=[*]
)
//Base Search
| (#repo="cloudtrail" OR #repo="fcs_csp_events") #Vendor="aws" #event.module="cloudtrail"
| #event.kind="event" #event.outcome="success"
| event.action=/^(?:Delete|Put|Create|Update|Attach|Detach|Run|Terminate|Modify|Authorize|Revoke|Restore|Schedule|Enable|Disable|InviteAccountToOrganization|AssumeRole)/
| time_bucket := formatTime("%Y-%m-%d %H", field=@timestamp)
| Vendor.userIdentity.arn =~ !in(values=["arn:aws:sts::555555555555:assumed-role/prod-hawk-large-codebuild-assume-role*", "arn:aws:sts::555555555555:assumed-role/cicd-test*"])
| Vendor.userIdentity.type =~ !in(values=["AWSAccount", "AWSService", "Unknown"])
| groupBy([time_bucket,Vendor.userIdentity.arn, Vendor.userIdentity.type],function=[count(as=mgmt_events_total_count), collect([event.action]), count(event.action, as=event_action_distinct_count, distinct=true)], limit=max)
| event_action_distinct_count>1
| match(file="mgmt_events_stats", field=Vendor.userIdentity.arn, strict=false)
| threshold := mgmt_events_average_count + 3 * mgmt_events_std_deviation_count
| case {
    threshold!=* | threshold := 0; // Identity with no activity in the baseline.
    *;
}
| test(mgmt_events_total_count > threshold)
```

**What This Demonstrates**:
- Historical baseline using `defineTable()` with 7-day lookback
- Statistical threshold calculation (mean + 3σ)
- Handling missing baseline data with `case` statement
- Filtering with regex on action names
- Excluding known service accounts with negative regex `!in()`
- Counting distinct values within aggregation

---

## Example 2: Temporal Correlation with selfJoinFilter

**Purpose**: Detect AWS IAM privilege escalation by correlating sequence of events (CreateUser → AttachUserPolicy with admin → CreateAccessKey/LoginProfile).

**Source**: `resources/detections/aws/aws___cloudtrail___iam_user_created_with_full_access_followed_by_access_key_or_password_creation.yaml`

**Key Techniques**:
- `selfJoinFilter()` for event sequencing
- Multi-step attack detection
- IP enrichment with `ipLocation()` and `asn()`

```cql
(#repo="cloudtrail" OR #repo="fcs_csp_events") #Vendor="aws"
| #event.kind="event" #event.outcome="success"
| event.action =~ in(values=["CreateUser", "AttachUserPolicy", "CreateAccessKey", "CreateLoginProfile"])
| selfJoinFilter([Vendor.userIdentity.arn, Vendor.requestParameters.userName],
    where=[
        { event.action="CreateUser" },
        { event.action="AttachUserPolicy" Vendor.requestParameters.policyArn="arn:aws:iam::aws:policy/AdministratorAccess" },
        { event.action =~ in(values=["CreateAccessKey", "CreateLoginProfile"]) }
    ], prefilter=true
)
| ipLocation(source.ip)
| asn(source.ip)
```

**What This Demonstrates**:
- Event sequencing with `selfJoinFilter()`
- Correlating events from same user
- Looking for specific action sequence (create → escalate → access)
- IP-based enrichment for investigation context
- Detecting multi-step attack patterns

---

## Example 3: Aggregation with Threshold Detection

**Purpose**: Detect AWS console brute force attacks by aggregating failed login attempts with volume thresholds.

**Source**: `resources/detections/aws/aws___cloudtrail___potential_brute_force_attack_on_iam_users_via_aws_management_console.yaml`

**Key Techniques**:
- `groupBy()` with multiple aggregate functions
- `distinct=true` for cardinality counting
- `collect()` for investigation context
- Multiple threshold conditions with OR

```cql
(#repo="cloudtrail" OR #repo="fcs_csp_events") #Vendor="aws" #event.module="cloudtrail"
| #event.kind="event" #event.outcome="failure"
| event.provider="signin.amazonaws.com" event.action="ConsoleLogin" event.reason="Failed authentication"
| Vendor.userIdentity.type="IAMUser"
| asn(source.ip)
| ipLocation(source.ip)
| groupBy([cloud.account.id, event.action, event.reason],
    function=[
        distinct_users := count(user.name, distinct=true),
        failed_logins := count(),
        collect([user.name, Vendor.userIdentity.principalId, source.ip.org, source.ip.country, source.ip.city, source.ip, Vendor.additionalEventData.MFAUsed, user_agent.original, #Vendor, #event.module, event.category[0]])
    ]
)
| failed_logins>=50 OR distinct_users>=10
```

**What This Demonstrates**:
- Aggregation with `groupBy()` on multiple fields
- Distinct counting with `count(field, distinct=true)`
- Collecting investigation context with `collect()`
- IP enrichment before aggregation
- Using OR conditions for different attack patterns
- Detecting both high-volume and wide-targeting attacks

---

## Example 4: Volume-Based Detection with Data Size Calculation

**Purpose**: Detect M365 data exfiltration by tracking excessive OneDrive/SharePoint downloads and converting byte counts to gigabytes.

**Source**: `resources/detections/microsoft/microsoft_-_m365_onedrive_sharepoint_-_excessive_data_download_activity.yaml`

**Key Techniques**:
- `coalesce()` for field fallback
- `sum()` aggregation for total bytes
- Mathematical operations for unit conversion
- `count(field, distinct=true)` for file counting

```cql
#Vendor="microsoft" #event.module="m365" (#event.dataset="m365.SharePoint" OR #event.dataset="m365.OneDrive") #repo!="xdr*"
| event.provider="SharePointFileOperation"
| event.action="FileDownloaded" OR event.action="FileSyncDownloadedFull"
| user.email!="app@sharepoint"
| coalesce([Vendor.FileSizeBytes, Vendor.FileSyncBytesCommitted], as="_fileSizeBytes")
| groupBy([#Vendor, #event.module, user.email, source.ip],
                        function=[sum(_fileSizeBytes, as=_totalBytes),
                                  count(Vendor.ObjectId, distinct=true, as="_fileCount"),
                                  collect([#event.dataset, event.action, organization.id, Vendor.GeoLocation, user_agent.original])])
| _totalGigaBytes := _totalBytes/1000000000
| _totalGigaBytes>100
```

**What This Demonstrates**:
- Field coalescing with `coalesce()` for API variation handling
- Sum aggregation with `sum(field, as=output_name)`
- Distinct counting for file cardinality
- Mathematical operations for unit conversion
- User exclusions for service accounts
- Data exfiltration volume thresholds

---

## Example 5: Multi-Platform Pattern Matching with Conditional Enrichment

**Purpose**: Detect CrowdStrike endpoints with default/suspicious hostnames across Windows, macOS, and Linux platforms.

**Source**: `resources/detections/crowdstrike/crowdstrike___endpoint___suspicious_hostname_or_ip_location.yaml`

**Key Techniques**:
- Platform-specific regex patterns in `case` statements
- Conditional enrichment with nested `case`
- CIDR subnet filtering with `cidr()`
- Lookup table matching

```cql
#repo="base_sensor"
| #event_simpleName="AgentOnline"
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
| ChassisType_decimal := ChassisType
| match(file="falcon/investigate/chassis.csv", column=ChassisType_decimal, field=ChassisType_decimal, include=ChassisType, strict=false)
| case {
    NOT cidr(aip, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
        | ipLocation(aip)
        | asn(aip);
    *
}
```

**What This Demonstrates**:
- Platform-specific pattern matching across Windows/Mac/Linux
- Regex patterns with case-insensitive flag `/i`
- Multiple conditions in single `case` block
- Lookup table matching with `match(file=...)`
- Conditional enrichment (only enrich external IPs)
- CIDR subnet filtering with `cidr()` and NOT operator
- Nested operations within case branches

---

## Example 6: File Type Classification with Named Capture Groups

**Purpose**: Detect M365 users collecting sensitive files by extension patterns and custom file naming conventions.

**Source**: `resources/detections/microsoft/microsoft_-_m365_onedrive_sharepoint_-_collection_of_sensitive_files_or_file_types.yaml`

**Key Techniques**:
- Named capture groups in regex: `(?<fieldname>pattern)`
- File extension categorization
- Multi-condition thresholds
- String manipulation with `lower()`

```cql
#Vendor="microsoft" #event.module="m365" (#event.dataset="m365.OneDrive" OR #event.dataset="m365.SharePoint") #repo!="xdr*"
| #event.kind="event" #event.outcome="success"
| event.provider="SharePointFileOperation" event.action="FileDownloaded"
| user.email!=app@sharepoint user.email=*
| file.extension := lower(file.extension)
| asn(client.ip)
| ipLocation(client.ip)

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
| groupBy(user.email, limit=max, function=[
    count(file.name, distinct=True, as=_distinct_files),
    count(file.extension, distinct=True, as=_distinct_extensions),
    collect([file.extension, file.confidentiality, event.action, Vendor.Site, Vendor.ListUrl, client.ip, client.ip.org, client.ip.country, user_agent.original])])

| _distinct_files>10 _distinct_extensions>2
```

**What This Demonstrates**:
- Named regex capture groups: `(?<file.confidentiality>PATTERN)`
- File extension categorization by risk type
- String normalization with `lower()` before comparison
- Multiple aggregation criteria (distinct files AND distinct extensions)
- Non-greedy regex matching with `?:` for grouping without capture
- Category-based detection logic (database files, source code, CAD files)
- Multi-condition thresholds requiring both diversity and volume

---

## Example 7: Session Hijacking Detection with String Formatting

**Purpose**: Detect AWS session hijacking by identifying access from multiple ASNs/networks for the same session.

**Source**: `resources/detections/aws/aws___cloudtrail___potential_session_hijacking.yaml`

**Key Techniques**:
- String formatting with `format()` for investigation output
- Time formatting with `formatTime()`
- ASN diversity detection
- Creating investigation-ready session details

```cql
(#repo="cloudtrail" OR #repo="fcs_csp_events") #Vendor="aws"
| #event.kind="event" #event.outcome="success"
| event.provider="health.amazonaws.com" event.action="DescribeEventAggregates"
| source.address!="health.amazonaws.com"
| _time := formatTime("%Y/%m/%d %H:%M:%S", field=@timestamp)
| ipLocation(source.ip)
| asn(source.ip)
| session_details := format("[%s] %s connected from %s %s %s %s\n  Source IP Org: %s\n  User Agent string: %s", field=[_time, user.name, source.ip, source.ip.country, source.ip.state, source.ip.city, source.ip.org, user_agent.original])
| groupBy([cloud.account.id, cloud.region, Vendor.userIdentity.arn, Vendor.userIdentity.type],
    function=[
        distinct_asn := count(source.ip.org, distinct=true),
        collect([source.ip.org, source.ip, session_details])
    ]
)
| distinct_asn>1
```

**What This Demonstrates**:
- Human-readable timestamp formatting with `formatTime()`
- Multi-line string formatting with `format()` and `\n`
- Creating investigation-ready output with context
- ASN-based diversity detection for session hijacking
- Collecting formatted session details for analyst review
- Using field interpolation in format strings with `field=[...]`

---

## Example 8: Simple Aggregation with Service Account Filtering

**Purpose**: Detect bulk GitHub branch deletions by a single user, filtering out automated merge queue operations.

**Source**: `resources/detections/github/github___multiple_branch_deletions.yaml` (lines 19-30)

**Key Techniques**:
- Basic groupBy() aggregation
- Service account filtering with custom function
- Simple threshold detection
- Selective bot exclusion

```cql
source_type=github
| Vendor.deleted="true"
| Vendor.sender.login=*

// Filter service accounts - exclude merge queue bot (customize per detection)
| $github_service_account_detector()
| github.service_account_type!="merge-queue"

// Aggregate by user
| groupBy([Vendor.sender.login, Vendor.organization.login], function=count(as=DeletionCount))
| test(DeletionCount >= 3)
```

**What This Demonstrates**:
- Calling saved search functions with `$function_name()`
- Post-filter approach for service accounts (detect first, then exclude specific types)
- Using test() for simple numeric threshold
- Aggregating on multiple keys (user + organization)
- GitHub event structure (Vendor.sender.login, Vendor.deleted, Vendor.organization.login)

---

## Example 9: Statistical Baseline with defineTable()

**Purpose**: Detect anomalous AWS KMS data key generation by comparing current activity against a 30-day baseline.

**Source**: `resources/detections/aws/aws_cloudtrail_kms_anomalous_data_key_generation.yaml` (lines 18-61)

**Key Techniques**:
- `defineTable()` for 30-day baseline calculation
- Baseline matching with `match(file=...)`
- Service account detection and filtering
- Handling users not in baseline (new behavior detection)

```cql
defineTable(
    query={
        #Vendor="aws" #event.module="cloudtrail" #repo!="xdr*"
        | #event.kind="event" #event.outcome="success"
        | event.provider="kms.amazonaws.com"
        | event.action =~ in(values=["GenerateDataKey", "GenerateDataKeyWithoutPlaintext", "GenerateDataKeyPair", "GenerateDataKeyPairWithoutPlaintext"])
        | Vendor.userIdentity.arn=*
        | user.name=*
        | _identity := coalesce([Vendor.userIdentity.arn, user.id])
        | groupBy([_identity, user.name, Vendor.requestParameters.keyId], function=[count(as="_baseline_count")])
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

// Main query
| #Vendor="aws" #event.module="cloudtrail" #repo!="xdr*"
| #event.kind="event" #event.outcome="success"
| event.provider="kms.amazonaws.com"
| event.action =~ in(values=["GenerateDataKey", "GenerateDataKeyWithoutPlaintext", "GenerateDataKeyPair", "GenerateDataKeyPairWithoutPlaintext"])
| Vendor.userIdentity.arn=*
| user.name=*

// Apply service account detection and filter to human users only
| $aws_service_account_detector(strict_mode="true", include_temp="false")
| aws.service_account_type!="hawk-service"
// TUNING: Exclude known service principals with access to Secrets
| user.name =~ !in(values=["awsreservedsso_team_secretsmanagement*", "*codebuild-assume-role"])

| _identity := coalesce([Vendor.userIdentity.arn, user.id])
| match(file="kms_key_generation", field=[_identity, user.name, Vendor.requestParameters.keyId], strict=false)
| case {
    _frequent_generator=false;  // User in baseline but not a frequent generator
    _frequent_generator!=*;       // User not in baseline at all (new behavior)
}
| groupBy([user.name, event.provider, event.action, Vendor.requestParameters.keyId], function=collect([event.provider, user.name, user.id, event.action, _frequent_generator, Vendor.requestParameters.keyId, cloud.region, user_agent.original, aws.service_account_type, aws.svc_detection_confidence]))
```

**What This Demonstrates**:
- defineTable() with 30-day lookback (start=30d, end=70m)
- Calculating baseline behavior (frequent vs infrequent generators)
- Matching current events against baseline with match(file=...)
- Detecting NEW behavior (users not in baseline with !=*)
- Service account filtering with custom function and parameters
- Negative regex exclusion with !in()
- Field coalescing for identity resolution

---

## Example 10: Multi-Tier Severity with Temporal Gating

**Purpose**: Detect brute force attacks with RAPID (15min), STANDARD (30min), and SUSTAINED (1h) detection tiers, using temporal gating to prevent duplicate alerts.

**Source**: `resources/detections/microsoft/microsoft_entra_id_multiple_failed_login_optimized.yaml` (lines 29-216)

**Key Techniques**:
- Multi-tier detection (3 severity levels with different time windows)
- Temporal gating (prevents duplicate alerts across executions)
- Pre-calculation of velocity metrics
- Attack pattern classification
- Risk scoring with multiple factors

```cql
// Get EntraID failed authentication events
#Vendor="microsoft" #event.dataset=/entraid/ #repo!="xdr*"
| array:contains(array="event.category[]", value="authentication")
| #event.kind="event" #event.outcome="failure"
| error.code=50126 user.name=*

// Normalize event ID field
| coalesce([Vendor.id, Vendor.properties.id], as="_event_id")
| $trusted_network_detector()

// Aggregate by user with rich context
| groupBy([user.name], function=[
    count(_event_id, as=TotalFailures, distinct=true),
    min(@timestamp, as=FirstAttempt),
    max(@timestamp, as=LastAttempt),
    count(source.ip, as=UniqueIPs, distinct=true),
    collect([source.ip], limit=10),
    selectLast([user.id, user.full_name]),
    count(Vendor.properties.appDisplayName, as=UniqueApps, distinct=true),
    count(Vendor.properties.deviceDetail.deviceId, as=UniqueDevices, distinct=true)
  ])

// TIME WINDOW CALCULATIONS - Post-aggregation
| _current_time := now()
| AttackDuration := (LastAttempt - FirstAttempt)
| AttackDurationMinutes := AttackDuration / 60000
| TimeSinceLastMinutes := (_current_time - LastAttempt) / 60000

// Pre-calculate velocity to avoid arithmetic in case statements
| _velocity_calc := TotalFailures / AttackDurationMinutes
| _failures_15m_ratio := TotalFailures * 15 / AttackDurationMinutes
| _failures_30m_ratio := TotalFailures * 30 / AttackDurationMinutes

| case {
    AttackDurationMinutes > 0 | AttackVelocity := _velocity_calc;
    * | AttackVelocity := TotalFailures;
  }

// Estimate failures in each time window
| case {
    TimeSinceLastMinutes <= 15 AND AttackDurationMinutes <= 15 | Failures_15m := TotalFailures;
    TimeSinceLastMinutes <= 15 AND AttackDurationMinutes > 15 | Failures_15m := _failures_15m_ratio;
    * | Failures_15m := 0;
  }

| case {
    TimeSinceLastMinutes <= 30 AND AttackDurationMinutes <= 30 | Failures_30m := TotalFailures;
    TimeSinceLastMinutes <= 30 AND AttackDurationMinutes > 30 | Failures_30m := _failures_30m_ratio;
    * | Failures_30m := 0;
  }

// Round to integers
| Failures_15m := math:floor(Failures_15m)
| Failures_30m := math:floor(Failures_30m)

// THRESHOLD LOGIC - Multi-tier detection
| case {
    Failures_15m >= 3 | DetectionTier := "RAPID" | Severity := 70 | ConfidenceLevel := "High";
    Failures_30m >= 5 | DetectionTier := "STANDARD" | Severity := 50 | ConfidenceLevel := "Medium";
    TotalFailures >= 8 | DetectionTier := "SUSTAINED" | Severity := 40 | ConfidenceLevel := "Medium";
    * | DetectionTier := "BELOW_THRESHOLD" | Severity := 0;
  }

| Severity > 0

// TEMPORAL GATING - Prevent duplicate alerts
| _alert_window_ms := 20 * 60 * 1000  // 20 minutes in milliseconds
| _cutoff_time := _current_time - _alert_window_ms
| test(LastAttempt > _cutoff_time)

// ATTACK PATTERN CLASSIFICATION
| case {
    UniqueIPs > 1 AND UniqueDevices > 1 | AttackPattern := "Distributed/Multiple Sources";
    UniqueIPs > 1 AND UniqueDevices = 1 | AttackPattern := "Multiple IPs/Same Device";
    UniqueIPs = 1 AND UniqueDevices > 1 | AttackPattern := "Same IP/Multiple Devices";
    UniqueApps > 2 | AttackPattern := "Multi-Application Spray";
    AttackVelocity > 1.0 | AttackPattern := "High-Velocity Attack";
    * | AttackPattern := "Single Source/Standard";
  }

// RISK SCORING
| case {
    DetectionTier = "RAPID" AND UniqueIPs > 1 | RiskScore := 90;
    DetectionTier = "RAPID" | RiskScore := 80;
    DetectionTier = "STANDARD" AND UniqueIPs > 2 | RiskScore := 70;
    DetectionTier = "STANDARD" | RiskScore := 60;
    DetectionTier = "SUSTAINED" AND UniqueApps > 2 | RiskScore := 55;
    * | RiskScore := 50;
  }
```

**What This Demonstrates**:
- Multi-tier detection with 3 severity levels (RAPID/STANDARD/SUSTAINED)
- Temporal gating to prevent duplicate alerts (LastAttempt > cutoff time)
- Pre-calculating velocity metrics to avoid arithmetic in test() functions
- Time window estimation (extrapolating total failures to specific windows)
- Attack pattern classification based on source diversity
- Dynamic risk scoring with multiple factors
- Using now() for current time reference
- Math functions: math:floor() for rounding
- Filtering after severity assignment (Severity > 0)
- Using AND in filter conditions (NOT in case statements!)

---

## Example 11: Geographic Risk with Privilege Multipliers

**Purpose**: Detect unauthorized international sign-ins with dynamic risk scoring based on destination country and user privilege level.

**Source**: `resources/detections/microsoft/microsoft_entraid_unauthorized_international_signin.yaml` (lines 14-103)

**Key Techniques**:
- Geographic risk classification (4 tiers: critical/high/medium/low)
- Privilege-based risk multipliers
- Composite risk calculation
- Dynamic severity determination
- Multi-function enrichment pipeline

```cql
#Vendor="microsoft" #event.dataset=/entraid\.signin/ #repo!="xdr*"
| array:contains(array="event.category[]", value="authentication")
| #event.outcome=success

// Get location information
| ipLocation(source.ip)

// Check if sign-in is from a country requiring authorization
| !in(field="source.ip.country", values=["US", "CA", "MX"])

// Extract user identity for group checking
| $entraid_enrich_user_identity()

// Check privileged group memberships including International Travel
| $entraid_check_privileged_groups(strict_mode="false", include_aws_groups="false")

// Alert only if user is NOT in International Travel group
| entra.has_international_access=false

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

// Add risk for privileged users accessing from risky locations
| case {
    entra.privilege_category="global_admin" AND CountryRisk!="low" | CompositeRiskScore := CompositeRiskScore + 25;
    entra.privilege_category="security_admin" AND CountryRisk!="low" | CompositeRiskScore := CompositeRiskScore + 20;
    entra.privilege_category="engineering_aws" AND CountryRisk!="low" | CompositeRiskScore := CompositeRiskScore + 15;
    * ;
  }

// Determine alert severity based on composite risk
| case {
    CompositeRiskScore >= 100 | AlertSeverity := "critical";
    CompositeRiskScore >= 75 | AlertSeverity := "high";
    CompositeRiskScore >= 50 | AlertSeverity := "medium";
    * | AlertSeverity := "low";
  }

// Build detailed alert information
| AlertTitle := format("Unauthorized International Sign-in: %s from %s",
    field=[entra.user_email, source.ip.country])

| AlertDescription := format(
    "User %s (Privilege: %s) successfully authenticated from %s (%s, %s) without International Travel authorization. Country Risk: %s, User has %d group memberships.",
    field=[entra.user_email, entra.privilege_category, source.ip.country, source.ip.city, source.ip, CountryRisk, group_count]
  )
```

**What This Demonstrates**:
- in() function for list membership checks (authorized countries, risk countries)
- NOT operator with in() for exclusion (!in)
- Geographic risk classification (4 tiers)
- Privilege-based risk multipliers (adding to base score)
- Composite risk calculation (base + privilege adjustments)
- Risk score bands for severity determination
- Multi-function enrichment pipeline ($entraid_enrich_user_identity + $entraid_check_privileged_groups)
- format() for creating human-readable alert titles and descriptions
- Using AND in filter conditions (not in case statements!)
- Negative equality checks (CountryRisk!="low")

---

## Common Patterns Across All Examples

### 1. IP Enrichment
```cql
| ipLocation(source.ip)
| asn(source.ip)
```
Used in: Examples 2, 3, 4, 6, 7, 11

### 2. Field Assignment and Creation
```cql
| threshold := mgmt_events_average_count + 3 * mgmt_events_std_deviation_count
| _totalGigaBytes := _totalBytes/1000000000
| time_bucket := formatTime("%Y-%m-%d %H", field=@timestamp)
```
Used in: All examples (1-11)

### 3. Distinct Counting
```cql
| count(field, distinct=true, as=output_name)
```
Used in: Examples 1, 3, 4, 6, 7, 10

### 4. Investigation Context Collection
```cql
| collect([field1, field2, field3, ...])
```
Used in: Examples 1, 3, 4, 6, 7, 9, 10

### 5. Conditional Logic with Case Statements
```cql
| case {
    condition1 | field := value1 ;
    test(comparison) | field := value2 ;
    * | field := default ;
}
```
Used in: Examples 1, 5, 6, 9, 10, 11

### 6. Field Coalescing and Fallback
```cql
| coalesce([field1, field2, field3], as=output_name)
```
Used in: Examples 4, 9, 10

### 7. String Formatting
```cql
| format("template %s %s", field=[field1, field2])
```
Used in: Examples 7, 11

### 8. Regex Pattern Matching
```cql
| field=/pattern/i
| field=/(?<captured_name>pattern)/
```
Used in: Examples 1, 5, 6

---

## Query Construction Best Practices (from Real Detections)

1. **Start with specific event filters** - Use tags like `#event_simpleName`, `#Vendor`, `#event.module`
2. **Filter early** - Apply exclusions before expensive operations like aggregation
3. **Enrich before aggregation** - Add geolocation/ASN data before groupBy when needed for aggregation keys
4. **Use meaningful field names** - Prefix temporary fields with `_` for clarity
5. **Collect investigation context** - Use `collect()` to gather relevant fields for analysts
6. **Apply thresholds last** - Aggregate first, then filter on computed values
7. **Format for readability** - Use `formatTime()` and `format()` to create human-readable output
8. **Handle missing data** - Use `case` statements to handle fields that may not exist
9. **Document with comments** - Explain complex logic, especially exclusions and thresholds
10. **Test incrementally** - Build queries step-by-step, validating each stage

---

## Performance Considerations from Production

- **Baseline queries**: Use `defineTable()` with appropriate time ranges (7d is common)
- **Early filtering**: Apply specific filters before aggregation to reduce data volume
- **Limit operations**: Use `limit=max` when you need all results, not just default 200
- **Distinct counts**: More expensive than regular counts, use only when needed
- **IP enrichment**: Apply after filtering to reduce enrichment operations
- **Regex complexity**: Complex patterns are expensive, filter to candidates first
- **Collect judiciously**: Only collect fields needed for investigation, not everything

---

## Testing These Queries

All queries above are deployed in production. To adapt for your environment:

1. **Adjust field names** - Your data source may use different field mappings
2. **Update exclusions** - Replace ARNs, accounts, emails with your known-good entities
3. **Tune thresholds** - Adjust counts and sizes based on your environment's baseline
4. **Add lookup files** - Ensure referenced CSV files exist (entraidusers.csv, etc.)
5. **Test on historical data** - Run against past data to validate before alerting
6. **Monitor false positives** - Refine exclusions based on false positive patterns
