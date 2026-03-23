# Available CQL Functions for Detection Enrichment

This catalog documents all 38 saved search functions available for detection tuning and enrichment. Functions are called using the `$function_name()` syntax in CQL queries.

## Complexity Legend

Functions are rated by implementation complexity to help you choose the right tool:

- **🟢 Simple**: Single-purpose, straightforward to use, few output fields
- **🟡 Moderate**: Multiple features, conditional logic, requires understanding of output fields
- **🔴 Advanced**: Complex multi-step enrichment, multiple dependencies, extensive output fields

---

## Core Identity Functions

### $identity_enrich_from_email()

**Complexity**: 🔴 Advanced

**Purpose**: Universal identity enrichment using EntraID as the authoritative identity provider source

**Location**: `resources/saved_searches/identity_enrich_from_email.yaml`

**Prerequisites**: UserEmail field must be set before calling this function

**Input Requirements**:
- UserEmail: lowercase email address (e.g., "john@company.com")

**Output Fields**:

| Field | Description |
|-------|-------------|
| id.display_name | Full display name from EntraID |
| id.department | User's department |
| id.job_title | User's job title |
| id.manager_name | Direct manager's name |
| id.manager_email | Direct manager's email |
| id.office_location | Office location or Remote |
| id.is_admin | Boolean - Has administrative privileges |
| id.is_contractor | Boolean - External contractor |
| id.is_engineer | Boolean - Engineering team member |
| id.is_executive | Boolean - Executive level |
| id.has_prod_access | Boolean - Has production access |
| id.has_github_access | Boolean - Has GitHub org access |
| id.is_service_account | Boolean - Service account flag |
| id.has_pim_eligibility | Boolean - Has PIM eligibility |
| id.is_quarantined | Boolean - Account quarantine status |
| id.trust_level | low/medium/high/elevated |
| id.trust_score | Numeric trust score (1-10) |
| id.risk_score | Numeric risk score (0-100) |
| id.privilege_tier | Privilege level (1-5, 1=highest) |
| id.account_type | service/user/admin/unknown |
| id.aws_username | Associated AWS IAM username |
| id.github_username | Associated GitHub username |
| id.admin_account | Associated admin account email |
| id.entra_object_id | EntraID object ID |
| id.entra_profile_link | Direct link to Entra profile |
| id.entra_signins_link | Direct link to Entra sign-ins |
| id.entra_audit_link | Direct link to Entra audit logs |
| id.user_identifier | Username portion (before @) |
| id.user_risk_profile | quarantined/privileged/executive/elevated_access/external/service/standard |
| id.enrichment_status | full/partial/email_only/none |

**Example Usage**:

```cql
// AWS CloudTrail events
#repo=cloudtrail
| $aws_enrich_user_identity()
| UserEmail := lower(aws.user_identity)
| $identity_enrich_from_email()
| id.is_admin="True"

// Google Workspace events
#Vendor="google"
| UserEmail := lower(actor.email)
| $identity_enrich_from_email()
| id.department="technology"

// Generic - any source with email field
| UserEmail := lower(user.email)
| $identity_enrich_from_email()
| id.has_prod_access="True"
```

**When to Use**: When you need comprehensive identity enrichment across multiple platforms (AWS, Google, Okta, etc.) using EntraID as the single source of truth. This is the universal enrichment function that works across all vendors.

**Usage Pattern** (Two-Tier Enrichment):
1. Extract identity using vendor-specific function (e.g., `$aws_enrich_user_identity()`)
2. Normalize to UserEmail field
3. Call `$identity_enrich_from_email()` for comprehensive enrichment

---

## AWS Identity Functions

### $aws_enrich_user_identity()

**Complexity**: 🟡 Moderate

**Purpose**: Extract and normalize user identity from AWS CloudTrail events

**Location**: `resources/saved_searches/aws_enrich_user_identity.yaml`

**Input Requirements**: AWS CloudTrail events with userIdentity structure

**Output Fields**:

| Field | Description |
|-------|-------------|
| aws.user_identity | Normalized user identifier (lowercase) |
| aws.user_type | CloudTrail identity type (IAMUser, AssumedRole, Root, etc.) |
| aws.actual_user_name | Extracted username from session or IAM |
| aws.identity_source | How identity was extracted (sso_federation, iam_user, etc.) |
| aws.user_domain | Domain extracted from email-based identities |
| aws.user_identifier | Username portion without domain |
| aws.role_name | Role name for AssumedRole types |
| aws.credential_type | temporary or long_term |
| aws.identity_context | Summary string |

**Example Usage**:

```cql
#repo=cloudtrail
| $aws_enrich_user_identity()
| groupBy([aws.user_type, aws.identity_source], function=count())
```

**When to Use**: First function to call for any AWS CloudTrail-based detection

---

### $aws_classify_identity_type()

**Complexity**: 🟡 Moderate

**Purpose**: Classify AWS identities into detailed human/service/system categories

**Location**: `resources/saved_searches/aws_classify_identity_type.yaml`

**Prerequisites**: Call `$aws_enrich_user_identity()` first (or set `include_service_detection="true"`)

**Parameters**:

| Parameter | Values | Description |
|-----------|--------|-------------|
| include_service_detection | "true"/"false" | Integrates with $aws_service_account_detector |

**Output Fields**:

| Field | Description |
|-------|-------------|
| aws.is_human_identity | Boolean - true for human actors |
| aws.identity_category | Detailed category (root_account, service_account, sso_user, etc.) |
| aws.identity_risk_score | Risk score (0-100) |
| aws.identity_risk_level | critical/high/medium/low/minimal |
| aws.identity_classification | Summary string |

**Identity Categories**:
- `root_account` - AWS root user (Risk: 90)
- `aws_service` - AWS service calls (Risk: 10)
- `service_account` - Detected service accounts (Risk: 20)
- `sso_user` - SSO federated users (Risk: 35)
- `human_iam_user` - Human IAM users (Risk: 40)
- `admin_role` - Administrative roles (Risk: 50)
- `cross_account` - Cross-account access (Risk: 70)

**Example Usage**:

```cql
#repo=cloudtrail
| $aws_enrich_user_identity()
| $aws_classify_identity_type(include_service_detection="true")
| aws.is_human_identity=true
```

**When to Use**: Filter out service accounts, focus on human actors, or assess identity risk

---

### $aws_service_account_detector()

**Complexity**: 🟡 Moderate

**Purpose**: Identify and flag AWS service accounts, automation users, and integration accounts

**Location**: `resources/saved_searches/aws_service_account_detector.yaml`

**Parameters**:

| Parameter | Values | Description |
|-----------|--------|-------------|
| strict_mode | "true"/"false" | Excludes ALL automation patterns |
| include_temp | "true"/"false" | Includes temporary/test account patterns |

**Output Fields**:

| Field | Description |
|-------|-------------|
| aws.is_service_account | Boolean - true for service accounts |
| aws.service_account_type | Category of service account |
| aws.svc_detection_confidence | high/medium/low/none |
| aws.service_account_reason | Explanation string |

**Detected Service Account Types**:

| Type | Examples |
|------|----------|
| monitoring | monitoring vendor, CrowdStrike CSPM |
| cicd | dev environment server, GitHub Actions |
| iac | Terraform, CloudFormation |
| aws-managed | AWSServiceRoleFor* |
| etl-pipeline | ETL tool |
| container-task | ECS Fargate, ECS Task |
| serverless | Lambda roles |
| platform-unit | Platform-specific services |
| data-platform | Data platform cross-account |

**Example Usage**:

```cql
#repo=cloudtrail
| $aws_service_account_detector()
| aws.service_account_type!="data-platform" AND aws.service_account_type!="iac"
```

**Best Practices**:

| Approach | When to Use | Risk |
|----------|-------------|------|
| `aws.service_account_type!="type1" AND aws.service_account_type!="type2"` | **Recommended** - Exclude specific expected service accounts per detection | Low - Maintains visibility |
| `aws.is_service_account=false` | **Avoid** - Only use when ALL service account activity is noise | High - May hide threats |

**Why Specific Exclusions Matter**:
- A monitoring service account launching EC2 instances is suspicious
- A data-platform service account launching GPU instances is expected
- Blanket `aws.is_service_account=false` would hide both - use specific types instead

**Common Exclusion Patterns by Detection Type**:

| Detection | Exclude These Types | Rationale |
|-----------|---------------------|-----------|
| EC2 instance launches | `data-platform`, `iac` | ML workloads and IaC provision instances |
| IAM changes | `iac`, `aws-managed` | Terraform manages IAM, AWS creates service roles |
| S3 access | `etl-pipeline`, `data-platform` | Data pipelines access S3 |
| Secrets access | `cicd`, `serverless` | CI/CD and Lambda need secrets |

**When to Use**: Exclude known automation before alerting - but be specific about which types

---

### $aws_extract_session_context()

**Complexity**: 🟡 Moderate

**Purpose**: Extract detailed session context from CloudTrail events

**Location**: `resources/saved_searches/aws_extract_session_context.yaml`

**Input Requirements**: CloudTrail events with session context

**When to Use**: Deep dive into session details for investigation

---

### $aws_validate_cross_account_trust()

**Complexity**: 🔴 Advanced

**Purpose**: Validate and classify AWS cross-account trust relationships

**Location**: `resources/saved_searches/aws_validate_cross_account_trust.yaml`

**Input Requirements**: AWS CloudTrail events with userIdentity and requestParameters

**Output Fields**:

| Field | Description |
|-------|-------------|
| aws.source_account | Origin AWS account ID |
| aws.target_account | Destination AWS account ID |
| aws.cross_account_trust_type | internal-trust, partner-trust, external-trust, unknown-* |
| aws.cross_account_risk | low/medium/high/critical |
| aws.cross_account_operation_type | role-assumption, role-creation, policy-update, etc. |
| aws.is_suspicious_pattern | Boolean flag for suspicious activity |
| aws.cross_account_user_name | Extracted username |
| aws.cross_account_role_name | Target role name |

**Example Usage**:

```cql
#repo=cloudtrail eventName=AssumeRole
| $aws_validate_cross_account_trust()
| aws.cross_account_risk="critical"
```

**When to Use**: Detect unauthorized cross-account access or trust policy changes

**Limitation**: Extracts target account from `roleArn` field - does not parse accounts from `policyDocument` JSON. For policy document parsing, use `$aws_classify_account_trust()` after extracting account IDs with regex.

---

### $aws_classify_account_trust()

**Complexity**: 🟢 Simple

**Purpose**: Classify an AWS account ID as internal org, known partner, or external

**Location**: `resources/saved_searches/aws_classify_account_trust.yaml`

**Input Requirements**: A field containing an AWS account ID (default: `accountId`)

**Output Fields**:

| Field | Description |
|-------|-------------|
| aws.account_trust_type | `internal`, `partner`, or `external` |
| aws.account_trust_risk | `low` (internal/partner) or `critical` (external) |
| aws.partner_name | Partner name if applicable (data platform, monitoring vendor, CrowdStrike, SASE vendor, analytics platform) |

**Example Usage**:

```cql
// For UpdateAssumeRolePolicy events - extract account from policy document first
| regex("arn:aws:iam::(?<accountId>\\d+):", field=Vendor.requestParameters.policyDocument, repeat=true)
| $aws_classify_account_trust()
| aws.account_trust_type="external"  // Only alert on unknown accounts
```

**When to Use**:
- When you need to classify an already-extracted account ID
- For policy document parsing where `$aws_validate_cross_account_trust()` shows `unknown-target`
- Simpler alternative when you only need account classification (not full cross-account context)

**Comparison with $aws_validate_cross_account_trust()**:

| Function | Use Case |
|----------|----------|
| `$aws_validate_cross_account_trust()` | AssumeRole events where roleArn contains target account |
| `$aws_classify_account_trust()` | Any event where you've extracted account ID separately (e.g., from policyDocument) |

---

### $aws_trusted_ip_detector()

**Complexity**: 🟢 Simple

**Purpose**: Identify trusted IP addresses and ranges for AWS access

**Location**: `resources/saved_searches/aws_trusted_ip_detector.yaml`

**When to Use**: Filter traffic from known-good IP ranges

---

## GitHub Functions

### $github_enrich_event_context()

**Complexity**: 🟡 Moderate

**Purpose**: Core enrichment function for all GitHub push events

**Location**: `resources/saved_searches/github_enrich_event_context.yaml`

**Input Requirements**: Events with source_type=github

**Output Fields**:

| Field | Description |
|-------|-------------|
| github.actor | GitHub username (from sender.login) |
| github.actor_email | Pusher email address |
| github.actor_type | Human/Bot/Organization/Unknown |
| github.repository | Repository name |
| github.repository_full_name | Full repository name (org/repo) |
| github.organization | Organization login |
| github.repo_visibility | public/private/internal |
| github.repo_language | Primary programming language |
| github.default_branch | Repository default branch |
| github.branch | Extracted branch name from ref |
| github.is_protected_branch | Boolean - main/staging/master |
| github.operation_type | ForcePush/BranchDelete/BranchCreate/TagPush/NormalPush |
| github.event_hour | Hour of event (00-23) |
| github.day_name | Day of week (Monday-Sunday) |
| github.is_business_hours | Boolean - Mon-Fri, 8-18 UTC |
| github.is_merge_queue | Boolean - Automated merge queue |

**Example Usage**:

```cql
source_type=github
| $github_enrich_event_context()
| github.is_protected_branch=true
| github.operation_type="ForcePush"
```

**When to Use**: First function to call for any GitHub detection. Provides essential context for all subsequent GitHub functions.

---

### $github_classify_sender_type()

**Complexity**: 🟡 Moderate

**Purpose**: Classify GitHub senders as human, bot, or organization with risk scoring

**Location**: `resources/saved_searches/github_classify_sender_type.yaml`

**Input Requirements**: Events with Vendor.sender.* fields

**Output Fields**:

| Field | Description |
|-------|-------------|
| github.sender_category | merge_queue/github_actions/dependabot/renovate/github_system/bot/human_user/organization/unknown |
| github.is_human_actor | Boolean - true for human users and organizations |
| github.sender_risk_score | Numeric risk score (5-50, lower = more trusted) |
| github.sender_classification | Summary string |

**Risk Scores by Category**:
- merge_queue: 5 (most trusted)
- github_system: 5
- github_actions: 10
- dependabot: 10
- renovate: 10
- bot: 15
- human_user: 30
- organization: 40
- unknown: 50 (highest risk)

**Example Usage**:

```cql
source_type=github
| $github_classify_sender_type()
| github.is_human_actor=true
| github.sender_risk_score >= 30
```

**When to Use**: When you need detailed sender classification with risk scoring for prioritization

---

### $github_service_account_detector()

**Complexity**: 🟢 Simple

**Purpose**: Identify and classify GitHub bots/service accounts for per-detection filtering

**Location**: `resources/saved_searches/github_service_account_detector.yaml`

**Output Fields**:

| Field | Description |
|-------|-------------|
| github.is_service_account | Boolean - true if identified as bot/automation |
| github.service_account_type | merge-queue/dependabot/github-actions/github-bot/human-user |
| github.svc_detection_confidence | high/medium/none |
| github.service_account_reason | Human-readable explanation |

**Example Usage**:

```cql
// Exclude only merge queue bot
source_type=github
| $github_service_account_detector()
| github.service_account_type!="merge-queue"

// Exclude all service accounts
source_type=github
| $github_service_account_detector()
| github.is_service_account=false

// Exclude multiple types
source_type=github
| $github_service_account_detector()
| github.service_account_type!="merge-queue"
| github.service_account_type!="dependabot"
```

**When to Use**: When you need fine-grained control over which bot types to exclude per detection. Use `github.service_account_type!="type"` for specific exclusions instead of blanket `aws.is_service_account=false`.

---

### $github_flag_risky_operations()

**Complexity**: 🟡 Moderate

**Purpose**: Flag high-risk Git operations with severity scoring

**Location**: `resources/saved_searches/github_flag_risky_operations.yaml`

**Prerequisites**: Call `$github_enrich_event_context()` before this function

**Input Requirements**: Events enriched with github.is_protected_branch and github.is_merge_queue fields

**Output Fields**:

| Field | Description |
|-------|-------------|
| github.risk_operation | ForcePushToProtected/ProtectedBranchDeletion/DirectPushToProtected/ForcePush/BranchDeletion/TagPush/Normal |
| github.operation_severity | Numeric severity (0-90) |
| github.risk_reason | Human-readable explanation |
| github.risk_level | critical/high/medium/low/none |
| github.is_risky_operation | Boolean - true for risky operations |

**Risk Levels**:
- **CRITICAL (90)**: Force push to protected branch
- **CRITICAL (80)**: Protected branch deletion
- **HIGH (70)**: Direct push to protected branch bypassing merge queue
- **HIGH (60)**: Force push to any branch
- **MEDIUM (30)**: Branch deletion
- **LOW (10)**: Tag push
- **NONE (0)**: Normal operations

**Example Usage**:

```cql
source_type=github
| $github_enrich_event_context()
| $github_flag_risky_operations()
| github.is_risky_operation=true
| github.operation_severity >= 70
```

**When to Use**: Prioritize alerts based on operation risk level, or filter to only critical/high risk operations

---

### $github_apply_exclusions()

**Complexity**: 🟢 Simple

**Purpose**: Filter out expected/benign GitHub activities to reduce noise in detections

**Location**: `resources/saved_searches/github_apply_exclusions.yaml`

**Input Requirements**: Events with Vendor.sender.* and Vendor.repository.* fields

**Output Fields**:

| Field | Description |
|-------|-------------|
| github.is_excluded | Boolean - true if should be filtered |
| github.exclusion_reason | Human-readable explanation |

**Excluded By Default**:
- github-merge-queue[bot]
- dependabot[bot]
- github-actions[bot]
- renovate[bot]
- Merge queue refs (gh-readonly-queue)

**Example Usage**:

```cql
source_type=github
| $github_apply_exclusions()
| github.is_excluded=false
```

**When to Use**: When you want all-or-nothing exclusion of known bots. For fine-grained control per detection, use `$github_service_account_detector()` instead.

**Comparison with $github_service_account_detector()**:

| Function | Use Case |
|----------|----------|
| `$github_apply_exclusions()` | All-or-nothing filtering - excludes all known bots |
| `$github_service_account_detector()` | Per-detection filtering - choose which bot types to exclude |

---

## Entra ID Functions

### Basic Identity Functions

#### $entraid_enrich_user_identity()

**Complexity**: 🟢 Simple

**Purpose**: Extract and normalize user identity from Entra ID events

**Location**: `resources/saved_searches/entraid_enrich_user_identity.yaml`

**Input Requirements**: Events with user identity fields from Entra ID logs

**Output Fields**:

| Field | Description |
|-------|-------------|
| entra.user_email | Normalized user email (lowercase) |
| entra.user_type | service_account, application_account, external_account, guest_account, user_account |
| entra.user_identifier | Username without domain |
| entra.user_domain | Email domain |

**Example Usage**:

```cql
#repo=microsoft_graphapi
| $entraid_enrich_user_identity()
| groupBy([entra.user_type], function=count())
```

**When to Use**: First function for any EntraID/Microsoft detection

---

#### $entraid_classify_user_type()

**Complexity**: 🟡 Moderate

**Purpose**: Enhanced user type classification using multiple data sources

**Location**: `resources/saved_searches/entraid_classify_user_type.yaml`

**Prerequisites**: Call `$entraid_enrich_user_identity()` and `$entraid_lookup_user_mapping()` first

**Parameters**:

| Parameter | Values | Description |
|-----------|--------|-------------|
| strict_mode | "true"/"false" | Classifies ambiguous accounts as non-human |
| include_contractors | "true"/"false" | Includes contractor classification details |

**Output Fields**:

| Field | Description |
|-------|-------------|
| entra.user_type_detailed | service_account/contractor/external_user/guest_user/automation_account/employee/human_user/potential_service/unclassified/unknown |
| entra.account_risk | low/medium/high |
| entra.is_service_account | Boolean - service/automation account |
| entra.is_external_user | Boolean - contractor/external/guest |
| entra.is_internal_human | Boolean - employee/human user |
| entra.user_risk_score | Numeric risk score (10-90) |
| ContractorCompany | Contractor company name (if applicable) |
| ContractorSponsor | Internal sponsor (if applicable) |

**Example Usage**:

```cql
#repo=microsoft_graphapi
| $entraid_enrich_user_identity()
| $entraid_lookup_user_mapping()
| $entraid_classify_user_type(strict_mode="false", include_contractors="true")
| entra.is_internal_human=true
```

**When to Use**: After basic enrichment when you need detailed classification with contractor/external user details

---

### Comprehensive Functions

#### $entraid_lookup_user_mapping()

**Complexity**: 🟡 Moderate

**Purpose**: Map user email to comprehensive identity information

**Location**: `resources/saved_searches/entraid_lookup_user_mapping.yaml`

**Prerequisites**: Call `$entraid_enrich_user_identity()` first

**Input Requirements**: Events with UserEmail field

**Output Fields**:

| Field | Description |
|-------|-------------|
| entra.object_id | EntraID object ID |
| entra.upn | User principal name |
| entra.display_name | Full display name |
| entra.employee_id | Employee ID |
| entra.department | Department name |
| entra.job_title | Job title |
| entra.manager_email | Manager's email |
| entra.manager_id | Manager's EntraID |
| entra.manager_name | Manager's name |
| entra.office_location | Office location |
| entra.created_date | Account creation date |
| entra.account_enabled | Boolean account status |
| entra.github_username | GitHub username |
| entra.aws_username | AWS IAM username |
| entra.department_category | technology/security/finance/human_resources/operations/business/governance/other/unknown |
| entra.is_account_disabled | Boolean - account disabled |
| entra.has_manager | Boolean - has manager assigned |
| entra.account_age | new_24h/new_week/new_month/recent_90d/established |
| entra.account_age_seconds | Numeric age in seconds |

**Example Usage**:

```cql
#repo=microsoft_graphapi
| $entraid_enrich_user_identity()
| $entraid_lookup_user_mapping()
| entra.department_category="technology"
| entra.account_age="new_week"
```

**When to Use**: Enrich with HR/directory data for investigations and correlation

---

#### $entraid_enrich_group_summary()

**Complexity**: 🔴 Advanced

**Purpose**: Add comprehensive group summary information from preprocessed data

**Location**: `resources/saved_searches/entraid_enrich_group_summary.yaml`

**Prerequisites**: UserEmail field must be set

**Parameters**:

| Parameter | Values | Description |
|-----------|--------|-------------|
| include_group_lists | "true"/"false" | Includes comma-separated group lists |
| group_detail_level | "minimal"/"standard"/"detailed" | Level of group detail |

**Output Fields**:

| Field | Description |
|-------|-------------|
| admin_groups | Comma-separated admin group names |
| engineering_groups | Comma-separated engineering group names |
| aws_groups | Comma-separated AWS group names |
| team_groups | Comma-separated TEAM group names |
| other_groups | Other group names |
| all_groups | All group names |
| github_orgs | GitHub organizations |
| group_count | Total group count |
| highest_privilege_group | Highest privilege group name |
| highest_privilege_tier | tier_1/tier_2/tier_3/tier_4/tier_5/none |
| entra.admin_group_count | Count of admin groups |
| entra.engineering_group_count | Count of engineering groups |
| entra.aws_group_count | Count of AWS groups |
| entra.team_group_count | Count of TEAM groups |
| entra.group_type_count | Count of different group types |
| entra.group_membership_pattern | no_groups/excessive_groups/diverse_access/standard_groups |
| entra.has_admin_groups | Boolean |
| entra.has_engineering_groups | Boolean |
| entra.has_high_risk_combination | Boolean - risky group combinations |
| entra.group_risk_score | Numeric risk score (0-90) |
| entra.group_summary | Summary string |
| entra.group_risk_violation | Boolean - risk >= 40 |
| entra.has_valid_group_membership | Boolean |

**Example Usage**:

```cql
#repo=microsoft_graphapi
| $entraid_enrich_user_identity()
| $entraid_enrich_group_summary(include_group_lists="true", group_detail_level="detailed")
| entra.has_high_risk_combination=true
```

**When to Use**: When you need comprehensive group membership analysis for access reviews and risk assessment

---

### Privileged Access Functions

#### $entraid_check_privileged_groups()

**Complexity**: 🟡 Moderate

**Purpose**: Check user membership in privileged security groups using preprocessed lookup data

**Location**: `resources/saved_searches/entraid_check_privileged_groups.yaml`

**Prerequisites**: UserEmail field must be set

**Parameters**:

| Parameter | Values | Description |
|-----------|--------|-------------|
| strict_mode | "true"/"false" | Only considers explicitly defined privileged groups |
| include_aws_groups | "true"/"false" | Includes AWS-related privileged groups |

**Output Fields**:

| Field | Description |
|-------|-------------|
| entra.has_global_admin | Boolean - Global/Security Administrator |
| entra.has_security_admin | Boolean - Security admin groups |
| entra.has_engineering_access | Boolean - Engineering groups |
| entra.has_aws_access | Boolean - AWS groups |
| entra.has_team_access | Boolean - TEAM groups |
| entra.privilege_level_score | Numeric score (0-5, 5=highest) |
| entra.privilege_category | global_admin/security_admin/engineering_aws/engineering/team_user/standard_user/no_groups |
| entra.in_privileged_category | Boolean - in privileged category |
| entra.is_privileged | Boolean - based on strict_mode |
| entra.group_risk_indicator | no_groups/excessive_groups/many_groups/normal_groups |
| entra.privilege_summary | Summary string |

**Example Usage**:

```cql
#repo=microsoft_graphapi
| $entraid_enrich_user_identity()
| $entraid_check_privileged_groups(strict_mode="true", include_aws_groups="true")
| entra.has_global_admin=true
```

**When to Use**: Filter or prioritize alerts based on privileged group membership

---

#### $entraid_check_team_eligibility()

**Complexity**: 🔴 Advanced

**Purpose**: Check TEAM and PIM eligibility status with activation tracking

**Location**: `resources/saved_searches/entraid_check_team_eligibility.yaml`

**Prerequisites**: UserEmail field must be set

**Parameters**:

| Parameter | Values | Description |
|-----------|--------|-------------|
| check_recent_activation | "true"/"false" | Includes recent activation checks |
| activation_window_hours | number | Hours to look back for recent activations (default 24) |

**Output Fields**:

| Field | Description |
|-------|-------------|
| team_group | TEAM group name |
| eligibility_type | permanent/eligible/none |
| is_member | Boolean - current member |
| requires_approval | Boolean - requires approval |
| max_duration_hours | Maximum activation duration |
| approver_group | Approver group name |
| last_activated | Last activation timestamp |
| activation_count_30d | Activations in last 30 days |
| entra.has_recent_activation | Boolean |
| entra.team_status | permanent_member/eligible_not_active/eligible_active/not_eligible/no_team_assignment/unknown |
| entra.team_approval_required | Boolean |
| entra.team_activation_pattern | never_activated/frequent_activation/regular_activation/occasional_activation/rare_activation |
| entra.team_risk_score | Numeric risk score (0-80) |
| entra.session_duration_violation | Boolean |
| entra.team_risk_category | high/medium/low/minimal |
| entra.is_valid_team_user | Boolean |
| entra.has_team_violation | Boolean |
| entra.team_summary | Summary string |

**Example Usage**:

```cql
#repo=microsoft_graphapi #event.category="management"
| $entraid_enrich_user_identity()
| $entraid_check_team_eligibility(check_recent_activation="true", activation_window_hours=24)
| entra.has_team_violation=true
```

**When to Use**: Detect TEAM privilege escalation violations, unauthorized access, or suspicious activation patterns

---

### Access Validation Functions

#### $entraid_validate_department_access()

**Complexity**: 🔴 Advanced

**Purpose**: Validate access based on department hierarchy and technical classifications

**Location**: `resources/saved_searches/entraid_validate_department_access.yaml`

**Prerequisites**: UserEmail and optionally Department fields must be set (call `$entraid_lookup_user_mapping()` first)

**Parameters**:

| Parameter | Values | Description |
|-----------|--------|-------------|
| validate_technical | "true"/"false" | Validates technical role requirements |
| strict_hierarchy | "true"/"false" | Enforces strict department hierarchy rules |

**Output Fields**:

| Field | Description |
|-------|-------------|
| entra.department_category | Department name |
| division | Division/business unit |
| team | Team within division |
| is_technical | Boolean - technical department |
| is_executive | Boolean - executive department |
| default_trust_level | Default trust level |
| requires_background_check | Boolean |
| entra.is_technical_access_valid | Boolean - technical access validation |
| entra.dept_privilege_alignment | aligned/no_privileges/misaligned |
| entra.hierarchy_violation | Boolean |
| entra.background_check_required | Boolean |
| entra.background_check_waived | Boolean |
| entra.dept_access_risk_score | Numeric risk score (0-115) |
| entra.dept_risk_category | high/medium/low/minimal |
| entra.has_dept_violation | Boolean - risk >= 40 |
| entra.dept_summary | Summary string |

**Example Usage**:

```cql
#repo=microsoft_graphapi #event.category="management"
| $entraid_lookup_user_mapping()
| $entraid_validate_department_access(validate_technical="true", strict_hierarchy="true")
| entra.has_dept_violation=true
```

**When to Use**: Enforce department-based access policies and detect privilege misalignment

---

#### $entraid_lookup_trust_level()

**Complexity**: 🟢 Simple

**Purpose**: Determine user trust level for authorization decisions

**Location**: `resources/saved_searches/entraid_lookup_trust_level.yaml`

**When to Use**: Assess user trust for privileged operations

---

#### $entraid_add_authorization_context()

**Complexity**: 🟡 Moderate

**Purpose**: Add authorization context for access decisions

**Location**: `resources/saved_searches/entraid_add_authorization_context.yaml`

**When to Use**: Before authorization checks

---

#### $entraid_flag_unauthorized_actions()

**Complexity**: 🟡 Moderate

**Purpose**: Flag actions that don't match user authorization

**Location**: `resources/saved_searches/entraid_flag_unauthorized_actions.yaml`

**When to Use**: Detect policy violations

---

#### $entraid_require_admin_authorization()

**Complexity**: 🟡 Moderate

**Purpose**: Require admin-level authorization for sensitive operations

**Location**: `resources/saved_searches/entraid_require_admin_authorization.yaml`

**When to Use**: Enforce admin requirements

---

### Device Audit Functions

#### $entraid_user_signin_audit()

**Complexity**: 🟡 Moderate

**Purpose**: Audit user sign-in patterns and anomalies

**Location**: `resources/saved_searches/entraid_user_signin_audit.yaml`

**When to Use**: Detect unusual sign-in patterns, impossible travel, or suspicious locations

---

#### $entraid_user_device_summary()

**Complexity**: 🟡 Moderate

**Purpose**: Summarize device count and compliance status per user

**Location**: `resources/saved_searches/entraid_user_device_summary.yaml`

**When to Use**: Device inventory and compliance checking

---

#### $entraid_user_app_device_summary()

**Complexity**: 🟡 Moderate

**Purpose**: Summarize application and device usage per user

**Location**: `resources/saved_searches/entraid_user_app_device_summary.yaml`

**When to Use**: Application access auditing combined with device context

---

#### $entraid_user_unregistered_devices()

**Complexity**: 🟢 Simple

**Purpose**: Identify unregistered or non-compliant devices

**Location**: `resources/saved_searches/entraid_user_unregistered_devices.yaml`

**When to Use**: Detect unauthorized device access

---

## Network & Connection Functions

### $trusted_network_detector()

**Complexity**: 🟡 Moderate

**Purpose**: Filter out Cloud SASE SASE/VPN connections and other trusted networks

**Location**: `resources/saved_searches/trusted_network_detector.yaml`

**Parameters**:

| Parameter | Values | Description |
|-----------|--------|-------------|
| extend_trust | "true"/"false" | Also exclude AWS internal, GitHub Actions |
| include_private | "true"/"false" | Also exclude RFC1918 private IP ranges |

**Output Fields**:

| Field | Description |
|-------|-------------|
| SourceIP | Extracted source IP |
| net.asn_org | ASN organization name |
| net.is_SASE | Boolean - true if Cloud SASE |
| net.is_excluded | Boolean - should be filtered |
| net.provider | sase-networks, aws-internal, github-actions, private-*, other |
| net.exclusion_reason | Explanation string |
| net.risk | excluded/unknown-asn/no-source-ip/review |

**Example Usage**:

```cql
#repo=cloudtrail
| $trusted_network_detector(extend_trust="true", include_private="true")
| net.is_excluded=false  // Only external/untrusted traffic
```

**When to Use**: Filter out corporate VPN traffic for external threat detection

---

### $sase_enrich_user_identity()

**Complexity**: 🔴 Advanced

**Purpose**: Enrich SASE SASE events with comprehensive user identity data

**Location**: `resources/saved_searches/sase_enrich_user_identity.yaml`

**Version**: 1.0 (Note: This function now provides full enrichment including EntraID data. For new detections, consider using `$identity_enrich_from_email()` for cross-platform consistency.)

**Input Requirements**: SASE events with user fields (Vendor.vpn_user_email, Vendor.user_name)

**Output Fields**: (Same as `$identity_enrich_from_email()` plus SASE-specific fields)

**SASE-Specific Fields**:

| Field | Description |
|-------|-------------|
| sase.status | Current connectivity status (connected/disconnected) |
| sase.connected_in_office | Boolean - connected from office network |
| sase.device_name | Device name from SASE |
| sase.last_connected | Last connection timestamp |

**Example Usage**:

```cql
#Vendor="sase"
| $sase_enrich_user_identity()
| id.is_admin="True"
| sase.status="disconnected"
```

**When to Use**: For SASE SASE events when you need both SASE connection context and full identity enrichment in a single function call

---

### $sase_validate_connection_source()

**Complexity**: 🟡 Moderate

**Purpose**: Validate and classify connection sources against Cloud SASE infrastructure

**Location**: `resources/saved_searches/sase_validate_connection_source.yaml`

**Input Requirements**: Events with source IP and optionally user email fields

**Output Fields**:

| Field | Description |
|-------|-------------|
| SourceIP | Extracted source IP |
| sase.is_sase_network | Boolean - IP in SASE CIDR ranges |
| sase.is_private_ip | Boolean - RFC1918 private IP |
| sase.connection_type | sase-network, internal-network, sase-user-external, external-direct |
| sase.connection_risk | low/medium/high |
| sase.status | User's SASE connection status (from lookup) |
| sase.connected_in_office | Boolean from SASE user data |
| sase.device_name | Device name from SASE |

**Example Usage**:

```cql
#repo=cloudtrail
| $sase_validate_connection_source()
| sase.connection_risk="high"
```

**When to Use**: Assess connection trust level and VPN usage

---

### $score_geo_risk()

**Complexity**: 🔴 Advanced

**Purpose**: Calculate geographic risk score based on IP location and user context

**Location**: `resources/saved_searches/score_geo_risk.yaml`

**Input Requirements**: Events with source.ip field

**Parameters**:

| Parameter | Default | Description |
|-----------|---------|-------------|
| alert_threshold | 60 | Risk score threshold for alerting |
| include_vpn_as_trusted | true | Reduces risk for VPN connections |

**Optional Dependencies**:
- `$sase_validate_connection_source()`: If called before, VPN trust adjustments apply

**Output Fields**:

| Field | Description |
|-------|-------------|
| Country | Geo-located country |
| City | Geo-located city |
| ASN, ASNOrg | ASN information |
| geo.is_authorized_country | Boolean - US/Canada/Mexico |
| geo.is_high_risk_country | Boolean - Russia/China/NK/Iran/etc. |
| geo.risk_score | Base risk score (10-100) |
| geo.adjusted_risk_score | Risk adjusted for user context |
| geo.risk_category | critical/high/medium/low/minimal |
| geo.vpn_adjusted_risk | Risk after VPN trust adjustment |
| geo.final_should_alert | Boolean alerting decision |

**Example Usage**:

```cql
#repo=cloudtrail
| $sase_validate_connection_source()
| $score_geo_risk()
| geo.final_should_alert=true
```

**When to Use**: Geographic anomaly detection for US-based workforce

---

## Baseline & Analytics Functions

### $create_baseline_7d() / $create_baseline_60d() / $create_baseline_90d()

**Complexity**: 🔴 Advanced

**Purpose**: Create statistical baselines for anomaly detection

**Locations**:
- `resources/saved_searches/create_baseline_7d.yaml` (7 days - rare events)
- `resources/saved_searches/create_baseline_60d.yaml` (60 days - standard patterns)
- `resources/saved_searches/create_baseline_90d.yaml` (90 days - long-term trends)

**Output**: Creates `baseline_stats` table with:

| Field | Description |
|-------|-------------|
| baseline.entity_id | User/resource identifier |
| baseline.event_type | Event name/action |
| baseline.avg | Average hourly count |
| baseline.std_dev | Standard deviation |
| baseline.max/baseline.min | Max and min values |
| baseline.data_points | Number of data points |
| baseline.p90/baseline.p95/baseline.p99 | Percentile values |

**Example Usage**:

```cql
#repo=cloudtrail
| $create_baseline_7d()
| match(file="baseline_stats", field=[baseline.entity_id, baseline.event_type], include=[baseline.avg, baseline.std_dev])
| threshold := baseline.avg + 3 * baseline.std_dev
| test(HourlyCount > threshold)
```

**When to Use**:
- **7d**: Rare or critical events, new patterns
- **60d**: Standard user behavior patterns
- **90d**: Long-term trends, seasonal patterns

---

## Function Chaining Best Practices

### AWS Detection Pipeline

```cql
#repo=cloudtrail
| $aws_enrich_user_identity()
| $aws_classify_identity_type(include_service_detection="true")
| $trusted_network_detector(extend_trust="true")
| $score_geo_risk()
| aws.is_human_identity=true
| net.is_excluded=false
| geo.final_should_alert=true
```

### GitHub Detection Pipeline

```cql
source_type=github
| $github_enrich_event_context()
| $github_classify_sender_type()
| $github_flag_risky_operations()
| $github_service_account_detector()
| github.is_human_actor=true
| github.is_risky_operation=true
| github.service_account_type!="merge-queue"
| github.operation_severity >= 70
```

### EntraID Detection Pipeline

```cql
#repo=microsoft_graphapi
| $entraid_enrich_user_identity()
| $entraid_lookup_user_mapping()
| $entraid_classify_user_type()
| $entraid_check_privileged_groups()
| $entraid_lookup_trust_level()
| $entraid_flag_unauthorized_actions()
```

### Universal Identity Enrichment Pipeline

```cql
// For any platform (Google, Okta, etc.)
#Vendor="google"
| UserEmail := lower(actor.email)
| $identity_enrich_from_email()
| id.is_admin="True"
| id.department="technology"
```

### Cross-Account Trust Detection

```cql
#repo=cloudtrail eventName=AssumeRole
| $aws_enrich_user_identity()
| $aws_validate_cross_account_trust()
| aws.cross_account_risk=~in(values=["critical", "high"])
| aws.is_suspicious_pattern=true
```

---

## Quick Reference Table

| Function | Vendor | Complexity | Purpose | Key Output |
|----------|--------|------------|---------|------------|
| $identity_enrich_from_email | Universal | 🔴 Advanced | Universal identity enrichment | id.display_name, id.department, id.is_admin, id.trust_level, Entra Links |
| $aws_enrich_user_identity | AWS | 🟡 Moderate | Extract identity | aws.user_identity, aws.user_type |
| $aws_classify_identity_type | AWS | 🟡 Moderate | Classify identity | aws.is_human_identity, aws.identity_risk_score |
| $aws_service_account_detector | AWS | 🟡 Moderate | Filter automation | aws.is_service_account, aws.service_account_type |
| $aws_extract_session_context | AWS | 🟡 Moderate | Session details | Session context fields |
| $aws_validate_cross_account_trust | AWS | 🔴 Advanced | Trust validation | aws.cross_account_risk, aws.cross_account_trust_type |
| $aws_classify_account_trust | AWS | 🟢 Simple | Account trust | aws.account_trust_type, aws.partner_name |
| $aws_trusted_ip_detector | AWS | 🟢 Simple | IP filtering | IP trust flags |
| $github_enrich_event_context | GitHub | 🟡 Moderate | Core enrichment | github.actor, github.repository, github.branch, github.operation_type |
| $github_classify_sender_type | GitHub | 🟡 Moderate | Sender classification | github.sender_category, github.is_human_actor, github.sender_risk_score |
| $github_service_account_detector | GitHub | 🟢 Simple | Bot detection | github.is_service_account, github.service_account_type |
| $github_flag_risky_operations | GitHub | 🟡 Moderate | Risk scoring | github.risk_operation, github.operation_severity, github.is_risky_operation |
| $github_apply_exclusions | GitHub | 🟢 Simple | Bot filtering | github.is_excluded, github.exclusion_reason |
| $entraid_enrich_user_identity | EntraID | 🟢 Simple | Extract identity | entra.user_email, entra.user_type |
| $entraid_classify_user_type | EntraID | 🟡 Moderate | Classify user | entra.user_type_detailed, entra.is_service_account, entra.is_external_user |
| $entraid_lookup_user_mapping | EntraID | 🟡 Moderate | User lookup | entra.department, entra.job_title, entra.department_category, entra.account_age |
| $entraid_enrich_group_summary | EntraID | 🔴 Advanced | Group summary | group_count, highest_privilege_tier, entra.group_membership_pattern |
| $entraid_check_privileged_groups | EntraID | 🟡 Moderate | Privileged check | entra.has_global_admin, entra.privilege_category, entra.privilege_level_score |
| $entraid_check_team_eligibility | EntraID | 🔴 Advanced | TEAM eligibility | entra.team_status, entra.team_risk_score, entra.is_valid_team_user |
| $entraid_validate_department_access | EntraID | 🔴 Advanced | Department validation | entra.is_technical_access_valid, entra.dept_access_risk_score |
| $entraid_lookup_trust_level | EntraID | 🟢 Simple | Trust level | User trust level |
| $entraid_add_authorization_context | EntraID | 🟡 Moderate | Authorization | Authorization context |
| $entraid_flag_unauthorized_actions | EntraID | 🟡 Moderate | Policy violations | Unauthorized flags |
| $entraid_require_admin_authorization | EntraID | 🟡 Moderate | Admin enforcement | Admin requirements |
| $entraid_user_signin_audit | EntraID | 🟡 Moderate | Sign-in audit | Sign-in anomalies |
| $entraid_user_device_summary | EntraID | 🟡 Moderate | Device summary | Device count, compliance |
| $entraid_user_app_device_summary | EntraID | 🟡 Moderate | App/device summary | App usage, device context |
| $entraid_user_unregistered_devices | EntraID | 🟢 Simple | Device audit | Unregistered devices |
| $trusted_network_detector | Any | 🟡 Moderate | Filter trusted networks | net.is_excluded, net.provider |
| $sase_enrich_user_identity | SASE | 🔴 Advanced | Full enrichment | All identity + sase.status, sase.device_name |
| $sase_validate_connection_source | Any | 🟡 Moderate | VPN validation | sase.connection_type, sase.connection_risk |
| $score_geo_risk | Any | 🔴 Advanced | Geographic risk | geo.final_should_alert, geo.risk_score |
| $create_baseline_7d | Any | 🔴 Advanced | 7-day baseline | baseline.avg, baseline.std_dev |
| $create_baseline_60d | Any | 🔴 Advanced | 60-day baseline | baseline.avg, baseline.std_dev |
| $create_baseline_90d | Any | 🔴 Advanced | 90-day baseline | baseline.avg, baseline.std_dev |
