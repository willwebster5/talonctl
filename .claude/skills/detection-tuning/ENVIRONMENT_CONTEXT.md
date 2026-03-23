# SOC AI Agent Environment Context

## Quick Reference for Detection Analysis

| Attribute | Value |
|-----------|-------|
| **Environment** | ~500 users, 100% cloud, US-based across all timezones |
| **SIEM** | CrowdStrike with OOTB detections for AWS, EntraID, Google (not Box/SASE) |
| **Alert Volume Target** | 0-5 alerts/day post-tuning |
| **High-Risk Users** | Executives and engineers (Mac users) with elevated privileges |
| **Critical Assets** | AWS Production account, SA admin accounts, sensitive PII in Box |

## Overview

This document provides environmental context for SOC AI Agents analyzing SIEM detections. It focuses on ingested data sources, baseline activities, and typical patterns to improve detection accuracy and reduce false positives.

---

## Data Sources & Baseline Activity

### 1. Google Workspace & GCP

- **Log Types**: Combined audit log stream
- **User Population**: ~500 active users
- **Primary Services**: Gmail, Drive, Calendar
- **Account Types**:
  - Standard users: FLast@acmecorp.com format
  - Admin accounts: FLastSA@acmecorp.com format
  - Service accounts for various automated processes
- **Administrative Structure**:
  - 3 Global Admins with SA accounts
  - 3 IT Support techs with limited admin roles (escalated as needed)
  - Key admin accounts:
    - admin1@acmecorp.com - Manual terminations/disabling accounts
    - admin2@acmecorp.com - Phishing investigations, blocklist management
- **GCP Services**:
  - Maps API (primary) - called from internal app (not yet in AWS)
  - Gemini API (some projects)
- **Baseline Activity**:
  - Higher activity during business hours for regular users
  - Map API calls on regular cadence for route formulation
  - Admin changes less frequent now (stabilized environment)
  - Normal admin activity: Account disabling, user archiving (when automation fails)
- **External Access**:
  - Contractors in separate OU: Global Settings > Temporary Staff (currently none active)
- **3rd Party Integrations**:
  - Box
  - KnowBe4
  - Users cannot self-approve/install integrations

### 2. AWS Infrastructure

- **Architecture**: Cloud-only, no on-premises infrastructure
- **Organization Structure**: 11 AWS accounts

| Account Name | Account ID | Purpose |
|-------------|------------|---------|
| Management | 111111111111 | Organization root |
| Identity | 222222222222 | Identity Center/SSO hub |
| Production | 333333333333 | Production workloads |
| Dev/UAT | 444444444444 | Development and testing |
| CICD | 555555555555 | Hosts dev environments |
| Security Audit | 666666666666 | Security monitoring |
| Log Archive | 777777777777 | Centralized logging |
| AcmePlatform | 888888888888 | Specific business unit/app |
| Hardware Sandbox | 999999999999 | Hardware team testing |
| Terraform Sandbox | 101010101010 | IaC testing |
| User Sandbox | 121212121212 | Individual sandbox |
| AI Sandbox | 131313131313 | AI/ML Sandbox |

- **Access Methods**:
  - Identity Center via EntraID SSO (68 synced users)
  - dev environment instances (GitHub SSO, two-step SSO backed)
  - AWS TEAM app for privilege elevation (PAM solution)
- **Developer Access Patterns**:
  - Default role: ReadOnly with inline policies
  - TEAM_* roles for elevation as needed
  - Primary work through dev environments
- **Key Services**:
  - RDS: Database hosting
  - ECS Fargate: Application hosting
  - Lambda: Various automation/functions
  - S3: Data storage
- **CI/CD & Automation**:
  - Terraform via GitHub Actions
  - OIDC trust: GitHub → Identity Account → Target Account (github-actions-role)
  - Deployments: Ad-hoc as needed
  - Manual admin access in sandbox/AI accounts for POCs
- **dev environments**:
  - Ephemeral instances (auto-shutdown, auto-delete after period)
  - Created via autoscaling
  - Full access within dev box environment
  - Access to certain secrets for functionality

### 3. SASE SASE Networks

- **Purpose**: VPN, web filtering, firewall for all corporate traffic
- **User Requirements**:
  - Mandatory connection for all 500 users
  - Geographic restriction: North America only (exceptions via EntraID exclusion group for approved international travel)
- **Connection Patterns**:
  - Users typically stay connected full workday
  - Intermittent reconnects due to SASE issues or user breaks
  - Minimal weekend/after-hours activity
  - No split tunneling - all traffic routes through SASE
- **Network Access Rules** (WAN/Internet Firewall):
  - Allow SSH for AWS: SASE Platform Team → AWS Organization
  - Allow Access to AWS: Multiple groups with various port access
  - Block SSH For Any: Default block rule for SSH
  - AI Access: Controlled via ChatGPT Teams Users, Claude Users groups
- **Groups**: EntraID synced groups control access levels
- **Security Monitoring**:
  - SASE alerts on potential malicious activity
  - Alerts not yet mapped to SIEM detections (raw logs only)
  - Few custom detections engineered (not OOTB)
  - Block events typically legitimate (low false positive rate)

### 4. EntraID (Microsoft)

- **Purpose**: SSO and identity management for all cloud applications
- **User Population**:
  - ~500 users (matches Google Workspace count)
  - 68 users synced to AWS Identity Center
  - Guest accounts created for contractors as needed
  - Service Account admins (SA format) similar to Google
- **Organization Structure**:
  - Dynamic groups based on department, job title, access requirements
  - Key department groups: Technology (46), Customer Success (98), Inside Sales (325), Outside Sales (41)
  - Engineering team groups: Blue Team (8), Green Team (8), Purple Team (7), Platform Team (12), Orange Team (7), Hardware Team (2), ML Team (1)
  - Special groups: PIM PAM Eligible Admins, Quarantined Users, International Travel
- **Security Features**:
  - EntraID Plan 2 with risk detection
  - MFA fully deployed (still allows SMS)
  - 24 active Conditional Access Policies including:
    - Block Access To Admin Portals
    - Block legacy authentication
    - Corporate Device Requirements for SASE
    - Geolocation Allow List
    - Sign-in Risk Policies (High, Medium)
    - User Risk Policy
    - Require MFA for various scenarios
- **SSO Applications** (70+ apps):
  - Major apps: AWS IAM Identity Center, Box, Slack, GitHub (3 orgs), project management, dev environment tool
  - Security tools: CrowdStrike, password manager, KnowBe4
  - Business apps: CRM, marketing platform, e-signature, expense management, accounting software, observability platform
- **Administrative Activity**:
  - Similar SA account structure as Google Workspace
  - Group management primarily through dynamic membership rules
  - Automated provisioning/deprovisioning (with manual fallback)

### 5. Box

- **Purpose**: Corporate file storage and document management
- **Security Features**: Box Shield for sensitive documents
- **Known Integrations**:
  - internal application (in AWS) - stores sensitive driver documents (tax forms, driver licenses, PII)
  - Potential finance/contracts usage
- **Access Patterns**:
  - SSO via EntraID
  - User provisioning likely via HR platform
- **Administrative Access**: IT department

### 6. GitHub Organization

- **Organization**: CompanyOrg
- **User Population**: Engineering team (~50-80 developers)
- **Repositories**: ~200+ repositories
- **Branch Protection**:
  - Protected branches: main, staging, master
  - Merge queue enabled on critical repos
- **Service Accounts & Bots**:
  - github-merge-queue[bot] - Automated branch merges
  - dependabot[bot] - Dependency updates
  - github-actions[bot] - CI/CD automation
  - renovate[bot] - Dependency management
- **Normal Activity**:
  - Merge queue performs ~20-50 automated merges/day
  - Dependabot creates ~5-10 PRs/week
  - Force pushes to feature branches (normal)
  - Direct pushes to protected branches (unusual - requires investigation)
- **High-Risk Operations**:
  - Protected branch deletion
  - Force push to protected branch
  - Direct push to main bypassing merge queue

---

## Statistical Baseline Guidance for 500-User Environment

### Baseline Window Selection

For an environment of ~500 users, baseline windows should account for:
- Enough data points for statistical significance
- Seasonal patterns (weekends, holidays, quarterly cycles)
- Recent system changes that might affect behavior

| Baseline Window | Use Case | Data Points | Considerations |
|----------------|----------|-------------|----------------|
| **7 days** | Rare/critical events | ~168 hours | Good for new patterns, may miss weekly cycles |
| **30 days** | Standard behavior | ~720 hours | Balanced, catches weekly patterns |
| **60 days** | Stable patterns | ~1,440 hours | More stable, less sensitive to outliers |
| **90 days** | Seasonal trends | ~2,160 hours | Catches quarterly patterns, may lag recent changes |

### Threshold Selection

For defining anomaly thresholds using statistical baselines:

| Formula | Sensitivity | False Positive Rate | Use Case |
|---------|-------------|---------------------|----------|
| `avg + 2*stddev` | High | 2-5% | Initial tuning, high-risk events |
| `avg + 3*stddev` | **Recommended** | <1% | Production alerting |
| `avg + 4*stddev` | Low | <0.1% | Critical-only alerts |
| `P_95` (95th percentile) | Variable | 5% | Alternative to stddev |
| `P_99` (99th percentile) | Low | 1% | High-confidence detection |

**Recommended Default**: `avg + 3*stddev` with 30-day baseline
- ~99.7% of normal activity falls below threshold
- <1% false positive rate in stable environments
- Adapts to user-specific behavior patterns

### Environment-Specific Anomaly Ratios

For a 500-user environment with cloud-only infrastructure:

**USB Exfiltration Baseline**:
- Normal: 50-200 MB/day per user
- Anomaly threshold: 2-3 GB/day (10-60x above normal)
- Justification: Cloud-first environment, limited legitimate USB transfer needs

**Failed Login Attempts**:
- Normal: 0-2 failures/day per user
- Anomaly threshold: 5+ failures in 30 minutes
- Justification: SSO reduces password failures, 5+ suggests brute force

**API Key Usage**:
- Normal: Stable daily pattern per service account
- Anomaly threshold: 3x above 30-day average
- Justification: Automated systems have predictable patterns

### Exclusion Windows

When establishing baselines, exclude recent data to prevent contamination:

| Baseline Window | Recommended Exclusion | Rationale |
|----------------|----------------------|-----------|
| 7-day | Last 2 hours | Real-time detection window |
| 30-day | Last 2 hours | Current detection period |
| 60-day | Last 24 hours | Allows for daily pattern completion |
| 90-day | Last 48 hours | Seasonal pattern stability |

---

## Privilege Group Context

### TEAM Users (Privileged Access Management)

- **System**: AWS TEAM app for privilege elevation
- **User Population**: ~68 users with TEAM eligibility
- **Access Patterns**:
  - TEAM_ReadOnly - Base access for investigations
  - TEAM_PowerUser - Elevated access for deployments
  - TEAM_Admin - Full admin access (rare, approved)
- **Detection Considerations**:
  - TEAM activations are logged in EntraID
  - Activations without recent usage suggest investigation
  - Multiple TEAM escalations in short window (unusual)
  - TEAM access from unexpected locations (high risk)

### EntraID Global Administrators

- **Count**: 3 global admin accounts (SA suffix)
- **Usage Pattern**: Infrequent, manual operations only
- **High-Risk Activities**:
  - Global admin login from non-SASE network
  - Global admin activity outside business hours
  - Global admin MFA changes
  - New global admin assignments
- **Detection Thresholds**: Zero-threshold for unexpected global admin activity

### Security Admin Group

- **Purpose**: SOC team, CSPM access, security tool management
- **User Count**: ~5-10 users
- **Expected Activities**:
  - Security log reviews
  - CSPM alert management
  - Security tool configuration
- **High-Risk Activities**:
  - Security admin creating service principals
  - Security admin modifying audit settings
  - Security admin disabling MFA for users

### Engineering + AWS Combined Access

- **Pattern**: Engineering team members with AWS access via TEAM
- **Risk Level**: Medium-high (broad access, technical capability)
- **Detection Considerations**:
  - Engineering + AWS + International location = High Risk
  - Engineering + AWS + Off-hours = Medium Risk
  - Engineering + Prod access requires extra validation

---

## Environment Characteristics

### Geographic Distribution

- All employees US-based
- Primary office: primary office (IT staff on-site, others remote)
- Mostly remote workforce across all US time zones
- Business hours: Eastern timezone primary, but activity across US timezones

### User Provisioning Flow

```
HR platform → EntraID → Google Workspace, Slack, and other apps
                   ↓
              SSO for most applications
```

### Infrastructure Summary

- **Company Size**: ~500 employees
- **Infrastructure**: 100% cloud (no on-premises)
- **Operations**:
  - No seasonal patterns
  - No regular maintenance windows
  - 24/7 availability expected for infrastructure

### Security Stack

| Layer | Tool |
|-------|------|
| SIEM | CrowdStrike with OOTB detections for AWS, EntraID, Google |
| EDR | CrowdStrike on all endpoints |
| Application Monitoring | Observability platform (not integrated with SIEM yet) |
| Network Security | SASE SASE |

### SOC Operations

- Senior Security Analyst handles alerts (AI will assist)
- Alert volume: 0-5 per day post-tuning
- No OOTB detections for Box or SASE (future possibility)

---

## Detection Considerations

### Service Account Patterns

**AWS Service Account Types (8 detected)**:
- monitoring (observability platform, CrowdStrike CSPM)
- cicd (dev environment server, GitHub Actions)
- iac (Terraform, CloudFormation)
- aws-managed (AWSServiceRoleFor*)
- etl-pipeline (ETL tool)
- container-task (ECS Fargate, ECS Task)
- serverless (Lambda roles)
- platform-unit/data-platform (business unit specific)

**GitHub Service Accounts & Bots**:
- `github-merge-queue[bot]` - Exclude from branch operation detections
- `dependabot[bot]` - Exclude from PR/commit detections
- `github-actions[bot]` - Context-dependent (normal for CI/CD, unusual for sensitive repos)
- Pattern: `[bot]` suffix indicates automation account

**EntraID Service Patterns**:
- Service accounts: svc-*, *-svc@
- Application accounts: app-*, application-*
- External/contractor: contractor, external, vendor, temp

### High-Value Targets

| Target Type | Examples | Risk Level |
|-------------|----------|------------|
| Admin Accounts | SA accounts (FLastSA@) | Critical |
| AWS Admins | 3 organization administrators | Critical |
| Global Admins | 3 EntraID global admins | Critical |
| GitHub Organization Owners | Organization owners | High |
| Production Access | AWS account 333333333333 | Critical |
| Executives | Executive team (Mac users) | High |
| Engineers | Engineering teams (Mac users with elevated access) | High |
| TEAM Eligible Users | Can elevate to admin (68 users) | High |
| EntraID Privileged Groups | Global Administrator (3 accounts) | Critical |
| Security Administrator | SOC team (~5-10 users) | High |
| Engineering + AWS Groups | High capability combination | High |

### Primary Threat Scenarios

1. **Compromise of executive accounts** (phishing, credential theft)
2. **Engineering team targeting** (supply chain, code injection)
3. **AWS infrastructure attacks** (privilege escalation, data exfiltration)
4. **Mac-specific threats** targeting high-value users

### Common False Positives to Consider

| Source | Pattern | Recommendation |
|--------|---------|----------------|
| SASE VPN | Intermittent disconnections/reconnections | Filter Cloud SASE ASN |
| Automation | Termination process failures requiring manual intervention | Exclude known SA accounts |
| dev environment tool | Engineers working through dev environments | Whitelist dev environment account patterns |
| Travel | International travel exceptions | Check EntraID exclusion group |
| Timezone | Cross-timezone activity | Consider all US timezones valid |
| GitHub Bots | Merge queue, Dependabot automated activity | Exclude [bot] accounts |

### Critical Monitoring Areas

- Privilege escalation via AWS TEAM app
- Access to sensitive data in Box (driver documents, PII)
- Production environment changes
- Admin account usage patterns (especially SA accounts)
- Cross-platform correlations (same user in multiple systems)
- Unusual activity from Mac endpoints (executives/engineers)
- After-hours access to critical systems
- Geographic anomalies (non-US access attempts)
- GitHub protected branch operations
- TEAM privilege elevation patterns

---

## Known Service Accounts and Automation

### AWS Service Accounts (from $aws_service_account_detector)

| Pattern | Type | Confidence |
|---------|------|------------|
| monitoring-integration | Monitoring | High |
| crowdstrikecspmreader | Security | High |
| githubactionsrole | CI/CD | High |
| terraform | IaC | High |
| etl-tool | ETL | Medium |
| ecs-fargate, lambda | Container/Serverless | Medium |
| dev-environment-server | Development | Medium |

### GitHub Service Accounts

| Account | Type | Normal Activity |
|---------|------|-----------------|
| github-merge-queue[bot] | Automation | Branch merges (20-50/day) |
| dependabot[bot] | Automation | Dependency PRs (5-10/week) |
| github-actions[bot] | CI/CD | Workflow executions |
| renovate[bot] | Automation | Dependency management |

### EntraID Service Patterns

- Service accounts: svc-*, *-svc@
- Application accounts: app-*, application-*
- External/contractor: contractor, external, vendor, temp

---

*Last Updated: February 2026*
