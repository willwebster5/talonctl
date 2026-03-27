# Playbook: AWS Cloud Security (FCS IoA + NGSIEM CloudTrail)

**Triggers on:**
- `fcs:` composite ID prefix — FCS Indicator of Attack (IoA) detections (e.g., SG modifications, RDS exposure, IAM changes)
- `ngsiem:` composite ID prefix + detection name containing "AWS" or "CloudTrail"

**Source:**
- FCS IoA: CrowdStrike Cloud Security out-of-the-box policies monitoring AWS CloudTrail
- NGSIEM CloudTrail: Custom NGSIEM correlation rules in `resources/detections/aws/`

**Tunable in NGSIEM:**
- FCS IoA (`fcs:` prefix): **No** — tune in Falcon Console > Cloud Security > IoA Policies
- NGSIEM CloudTrail (`ngsiem:` prefix): **Yes** — detection templates in `resources/detections/aws/`

## What These Alerts Mean

### FCS IoA (Cloud Security)
CrowdStrike Cloud Security monitors AWS CloudTrail in real-time using built-in IoA policies. These fire on cloud-native threat patterns: SG modifications exposing resources, IAM privilege escalation, data store exposure, etc. The alert payload from `alert_analysis` includes rich cloud context: AWS account ID, region, resource IDs, API action, actor identity, and policy details.

### NGSIEM CloudTrail (Custom Detections)
Custom correlation rules written in CQL that query CloudTrail logs ingested into NGSIEM. These detections live in `resources/detections/aws/` and are tunable via template editing. They complement FCS by covering org-specific patterns (e.g., cross-account trust, service account abuse, dev environment tool environment activity).

**Note:** The same CloudTrail event can trigger BOTH an FCS IoA alert and an NGSIEM detection. They are independent systems monitoring the same data source.

## Cloud Asset Verification Workflow

**Key insight: CloudTrail tells you WHO did WHAT; cloud assets tell you the CURRENT STATE.**

After reviewing the alert payload, verify the affected resource's current configuration:

### Security Groups
```
mcp__crowdstrike__cloud_query_assets(resource_id="sg-xxxxxxxx")
```
Returns: inbound/outbound rules, VPC, tags, `publicly_exposed` flag. Check whether the SG change (a) is still in effect and (b) actually exposes anything to the internet.

### RDS Instances
```
mcp__crowdstrike__cloud_query_assets(resource_id="my-rds-instance-name")
```
Returns: engine, version, `publicly_accessible` flag, encryption status, VPC/subnet, backup configuration. Check whether the instance is actually exposed.

### EC2 Instances
```
mcp__crowdstrike__cloud_query_assets(resource_id="i-xxxxxxxx")
```
Returns: instance type, state, security groups, IAM role, public IP, tags.

### Account-Level Posture
```
mcp__crowdstrike__cloud_get_iom_detections(account_id="<aws_account_id>", severity="high")
mcp__crowdstrike__cloud_get_risks(account_id="<aws_account_id>", severity="critical")
```

## Base Query Filter

All AWS CloudTrail investigation queries should start with this base:

```cql
(#repo="cloudtrail" OR #repo="fcs_csp_events") #Vendor="aws" #repo!="xdr*"
```

## Investigation Queries

### 1. Actor's CloudTrail Activity Around Alert Time (1h window)

Full activity for the actor who triggered the alert. Use the `Vendor.userIdentity.arn` from the alert payload.

```cql
(#repo="cloudtrail" OR #repo="fcs_csp_events") #Vendor="aws" #repo!="xdr*"
| Vendor.userIdentity.arn="{{actor_arn}}"
| table([@timestamp, event.provider, event.action, #event.outcome, cloud.account.id, cloud.region, source.ip, Vendor.userIdentity.type, user_agent.original], limit=100, sortby=@timestamp, order=desc)
```
**Time range:** 1h (centered on alert timestamp)

### 2. All Modifications to Affected Resource (7d)

Track all changes to a specific resource (e.g., security group, RDS instance). Substitute the resource identifier into the query.

**For Security Groups:**
```cql
(#repo="cloudtrail" OR #repo="fcs_csp_events") #Vendor="aws" #repo!="xdr*"
| event.provider="ec2.amazonaws.com"
| Vendor.requestParameters.groupId="{{sg_id}}"
| table([@timestamp, event.action, #event.outcome, Vendor.userIdentity.arn, source.ip, cloud.account.id, cloud.region], limit=50, sortby=@timestamp, order=desc)
```
**Time range:** 7d

**For RDS Instances:**
```cql
(#repo="cloudtrail" OR #repo="fcs_csp_events") #Vendor="aws" #repo!="xdr*"
| event.provider="rds.amazonaws.com"
| Vendor.requestParameters.dBInstanceIdentifier="{{rds_instance_name}}"
| table([@timestamp, event.action, #event.outcome, Vendor.userIdentity.arn, source.ip, cloud.account.id, cloud.region], limit=50, sortby=@timestamp, order=desc)
```
**Time range:** 7d

### 3. Security Group Modification History in Account (7d)

All SG changes across the account — useful for detecting a pattern of weakening network controls.

```cql
(#repo="cloudtrail" OR #repo="fcs_csp_events") #Vendor="aws" #repo!="xdr*"
| event.provider="ec2.amazonaws.com"
| event.action=/(Authorize|Revoke)SecurityGroup(Ingress|Egress)/
| cloud.account.id="{{account_id}}"
| table([@timestamp, event.action, Vendor.requestParameters.groupId, Vendor.userIdentity.arn, source.ip, #event.outcome, cloud.region], limit=50, sortby=@timestamp, order=desc)
```
**Time range:** 7d

### 4. RDS Events for Specific Instance (7d)

All RDS API calls for an instance — snapshots, modifications, restores, deletions.

```cql
(#repo="cloudtrail" OR #repo="fcs_csp_events") #Vendor="aws" #repo!="xdr*"
| event.provider="rds.amazonaws.com"
| Vendor.requestParameters.dBInstanceIdentifier="{{rds_instance_name}}" OR Vendor.responseElements.dBInstanceIdentifier="{{rds_instance_name}}"
| table([@timestamp, event.action, #event.outcome, Vendor.userIdentity.arn, source.ip, cloud.account.id], limit=50, sortby=@timestamp, order=desc)
```
**Time range:** 7d

### 5. Same Actor Across All AWS Accounts (24h)

Check if the actor operated in other AWS accounts (lateral movement across org).

```cql
(#repo="cloudtrail" OR #repo="fcs_csp_events") #Vendor="aws" #repo!="xdr*"
| Vendor.userIdentity.arn=/{{actor_name_pattern}}/
| groupBy([cloud.account.id, Vendor.userIdentity.arn], function=[
    count(as=total_events),
    count(event.action, distinct=true, as=distinct_actions),
    collect([event.provider, event.action, source.ip])
  ], limit=max)
| sort(total_events, order=desc)
```
**Time range:** 24h

### 6. IAM Privilege Escalation Pattern (24h)

Detect escalation: actor creates/modifies IAM policies, then assumes roles or performs high-privilege actions.

```cql
(#repo="cloudtrail" OR #repo="fcs_csp_events") #Vendor="aws" #repo!="xdr*"
| event.provider="iam.amazonaws.com"
| event.action=/(CreatePolicy|PutRolePolicy|AttachRolePolicy|CreateRole|AssumeRole|PutUserPolicy|AttachUserPolicy)/
| cloud.account.id="{{account_id}}"
| table([@timestamp, event.action, #event.outcome, Vendor.userIdentity.arn, Vendor.userIdentity.type, source.ip, cloud.region], limit=50, sortby=@timestamp, order=desc)
```
**Time range:** 24h

### 7. Cross-Source Correlation for Actor (24h)

Check what else this actor did across ALL log sources (EntraID, SASE, Google).

```cql
"{{actor_email_or_name}}"
| #repo!="xdr*"
| table([@timestamp, #Vendor, #Product, #event.dataset, event.action, source.ip, #event.outcome], limit=50, sortby=@timestamp, order=desc)
```
**Time range:** 24h (centered on alert timestamp)

## AWS Account Reference

| Account | ID | Risk Level | Notes |
|---|---|---|---|
| Management | 111111111111 | Critical | Organization root |
| Identity | 222222222222 | Critical | Identity Center/SSO hub |
| Production | 333333333333 | Critical | Production workloads |
| Security Audit | 444444444444 | High | Security monitoring |
| Dev/UAT | 555555555555 | Medium | Development and testing |
| CICD | 666666666666 | Medium | dev environments |
| Log Archive | 777777777777 | High | Centralized logging |
| AcmePlatform | 888888888888 | Medium | Business unit app |
| Hardware Sandbox | 999999999999 | Low | Hardware team testing |
| Terraform Sandbox | 101010101010 | Low | IaC testing |
| AI/ML Sandbox | 131313131313 | Low | AI/ML team experimentation (replaced prior AI account) |
| Legacy | 121212121212 | Medium | Legacy account — S3 buckets for staging/prod apps. S3 access from app roles is expected; manual/admin activity is NOT. |

## Triage Checklists

### FCS IoA Alerts

1. **What IoA policy triggered?** Read the policy_name and policy_id from the alert payload. Understand what cloud behavior it's detecting.
2. **Which AWS account?** Cross-reference with the account table above. Sandbox/low-risk accounts have different thresholds than Production/Identity.
3. **Who is the actor?** Check `Vendor.userIdentity.arn` — is this a known service role (github-actions-role, dev environment tool, Terraform), a TEAM elevation, or a human user?
4. **Verify current resource state**: Call `cloud_query_assets(resource_id=...)` to check if the flagged configuration is still in effect and whether it actually creates exposure.
5. **Is this automation?** Check user_agent for Terraform (`APN/1.0 HashiCorp/...`), dev environment tools, monitoring agents, or other known automation patterns.
6. **Is the resource exposed?** The `publicly_exposed` flag from `cloud_query_assets` is the ground truth. A SG change that doesn't result in public exposure is lower risk.

### NGSIEM CloudTrail Alerts

1. **Find the detection template**: Search `resources/detections/aws/` for the alert name. Read the CQL filter to understand exactly what triggered.
2. **Which AWS account?** Same account risk assessment as above.
3. **Who is the actor?** Check identity ARN against known service accounts, automation roles, and TEAM elevations.
4. **Is this a known CI/CD pattern?** GitHub Actions from Azure IPs with Terraform user agents from the CICD account is expected.
5. **What was the impact?** Use CloudTrail queries above to understand the full scope of the actor's activity.
6. **Check existing tuning**: Does the detection already have enrichment functions (`$aws_service_account_detector()`, `$aws_classify_account_trust()`)? If so, why didn't they filter this event?

### RDS-Specific Alerts

1. **Is the instance publicly accessible?** Call `cloud_query_assets(resource_id="<rds_instance_name>")` — check the `publicly_accessible` flag.
2. **Was this a restore operation?** RDS restore-from-snapshot creates a new instance with default settings (potentially public). Check `event.action` for `RestoreDBInstanceFromDBSnapshot`.
3. **CloudTrail gap**: Some RDS operations (automated snapshots, internal maintenance) are AWS-initiated and may not appear in CloudTrail. Absence of evidence is not evidence of absence.
4. **Check the security group**: RDS instances inherit their SG. Call `cloud_query_assets(resource_id="<sg_id>")` to verify the SG rules.

## Common FP Patterns

### FCS IoA False Positives

| FP Pattern | How to Identify | Resolution |
|---|---|---|
| Terraform CI/CD deployments | Actor ARN contains `github-actions-role`, user_agent contains `APN/1.0 HashiCorp/`, source IP from Azure ranges | Known automation from CICD account (666666666666). Tune in FCS IoA policy if volume warrants. |
| dev environment tool dev environment provisioning | Activity from CICD account, EC2/SG changes for ephemeral instances | Expected developer activity. dev environments are ephemeral. |
| Monitoring agent | Actor is monitoring service role, read-only API calls | Monitoring infrastructure, not a threat. |
| TEAM privilege elevation | Role ARN contains `TEAM_*`, corresponds to approved PAM session | Authorized elevation via AWS TEAM app. |
| Sandbox account activity | Account ID in [999999999999, 101010101010, 121212121212] | Manual admin access for POCs is expected in sandbox accounts. |

### NGSIEM AWS CloudTrail False Positives

| FP Pattern | How to Identify | Resolution |
|---|---|---|
| GitHub Actions CI/CD | `github-actions-role` + Terraform UA + Azure IPs | Exclude via `$aws_service_account_detector()` or role name filter |
| dev environment tool ephemeral instances | EC2/SG events from CICD account (666666666666) | Exclude CICD account or dev environment tool-specific patterns |
| TEAM elevation | `TEAM_*` role assumptions | Already filtered by `$aws_classify_session_type()` in most detections |
| Cross-account trust (authorized) | AssumeRole from known org accounts | Use `$aws_classify_account_trust()` to classify trust level |
| RDS automated operations | `event.provider="rds.amazonaws.com"`, actor is `rds.amazonaws.com` (AWS service) | AWS-initiated, not human activity |

## Closing the Alert

**FP — FCS IoA:**
```
mcp__crowdstrike__update_alert_status(
  status="closed",
  comment="FP — <reason>. FCS IoA alert, tune in Cloud Security IoA policy <policy_id>",
  tags=["false_positive", "cloud_security"]
)
```

**FP — NGSIEM CloudTrail:**
```
mcp__crowdstrike__update_alert_status(
  status="closed",
  comment="FP — <reason>. Tuned: <description of template change>",
  tags=["false_positive", "tuned"]
)
```
Then proceed to Phase 3B to edit the detection template in `resources/detections/aws/`.

**TP:**
Escalate via Phase 3C workflow.
```
mcp__crowdstrike__update_alert_status(
  status="in_progress",
  comment="TP confirmed: <summary>",
  tags=["true_positive"]
)
```

## CloudTrail Visibility Gaps

**Important caveats** when investigating AWS CloudTrail:
- **AWS service-initiated actions** (automated RDS snapshots, internal SG evaluations, Lambda warm-up) may not produce CloudTrail events
- **Eventual consistency**: CloudTrail events can be delayed up to 15 minutes from the actual API call
- **Data events** (S3 object-level, Lambda invocations) require explicit trail configuration — they may not be logged
- **Cross-account**: Events appear in the account where the API call lands, not necessarily where the actor originates. Check both source and destination accounts.
