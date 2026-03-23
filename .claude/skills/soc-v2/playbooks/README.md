# SOC Investigation Playbooks

Pre-built investigation playbooks with **verified CQL queries** extracted from production detection templates. These eliminate field-name guessing during triage.

## How to Use

1. **Match the alert type** to the right playbook using the table below
2. **Copy investigation queries** and substitute placeholders: `{{user}}`, `{{ip}}`, `{{timerange}}`
3. **Follow the triage checklist** before classifying TP/FP

## Playbook Index

| Alert Source | Composite ID Prefix | Playbook | Covers |
|---|---|---|---|
| EntraID Sign-In (3rd Party) | `thirdparty:` | [entraid-signin-alert.md](entraid-signin-alert.md) | Third-party sign-in-activity alerts from EntraID connector |
| EntraID Risky Sign-In / Account Security (NGSIEM) | `ngsiem:` | [entraid-risky-signin.md](entraid-risky-signin.md) | Risky sign-ins, AiTM, PRT abuse, account lockout, MFA denied, password spray |
| AWS Cloud Security (FCS IoA) | `fcs:` | [cloud-security-aws.md](cloud-security-aws.md) | SG modifications, RDS exposure, IAM changes, cloud-native threat patterns |
| AWS CloudTrail (NGSIEM) | `ngsiem:` | [cloud-security-aws.md](cloud-security-aws.md) | Custom CloudTrail detections — console logins, privilege escalation, resource modifications |
| Container/ECS (Operational) | N/A | [container-sensor-investigation.md](container-sensor-investigation.md) | Container sensor increases, ECS Fargate telemetry, new deployments |
| KnowBe4 PhishER — Threat Link DNS | `ngsiem:` | [knowbe4-phisher.md](knowbe4-phisher.md) ⚠️ WIP | PhishER link/DNS correlation, image CDN FPs, redirect cloakers, click-through verification |

**Future playbooks** — add these after the first real investigation of each type:
- SASE VPN (connectivity anomalies, geo-anomalies)
- Endpoint EDR (process execution, LOLBins, lateral movement)
- Google Workspace (admin actions, OAuth grants)

## EntraID Field Schema Reference

### Sign-In Logs
```
#Vendor="microsoft"
#event.dataset=/entraid\.signin/ or #event.dataset="azure.entraid.signin"
#event.module="entraid" or #event.module="azure"
#repo in: "microsoft_graphapi", "3pi_microsoft_entra_id", "fcs_csp_events"
```

**User identity:**
- `user.email` — UPN (Graph API / azure parser)
- `user.full_name` — UPN (entraid parser)
- Always coalesce: `coalesce([user.email, user.full_name], as=_userPrincipalName)`
- `user.id` — EntraID object ID

**Network / Geo:**
- `source.ip` — source IP address
- `source.geo.city_name` — city
- `source.geo.country_name` — country
- Use `asn(source.ip)` to get `source.ip.org` (ISP/ASN)
- Use `ipLocation(source.ip)` for `source.ip.country`, `source.ip.state`, `source.ip.city`

**Authentication result:**
- `#event.outcome` — "success" or "failure"
- `error.code` — string error code ("0" = success)
- `error.message` — error description
- `Vendor.status.errorCode` — numeric error code (50053=locked, 50057=disabled, 50126=bad password, 53003=CA blocked)
- `Vendor.status.failureReason` — failure reason text
- `Vendor.conditionalAccessStatus` — "success", "failure", "notApplied"

**Risk assessment (dual-schema — always coalesce):**
- `Vendor.riskLevelDuringSignIn` / `Vendor.properties.riskLevelDuringSignIn` — "none", "low", "medium", "high"
- `Vendor.riskState` / `Vendor.properties.riskState` — "atRisk", "confirmedCompromised", "remediated", "none"
- `Vendor.riskEventTypes_v2[]` / `Vendor.properties.riskEventTypes_v2[]` — risk event type array

**Application / Session:**
- `Vendor.appDisplayName` / `Vendor.properties.appDisplayName` — app name
- `Vendor.appId` / `Vendor.properties.appId` — app GUID
- `Vendor.correlationId` / `Vendor.properties.correlationId` — sign-in correlation ID
- `event.action` — action name (e.g., "sign-in-activity")
- `event.provider` — "SignInLogs", "AuditLogs"

**Device / Auth method:**
- `Vendor.AuthenticationRequirement` — "singleFactorAuthentication", "multiFactorAuthentication"
- `Vendor.DeviceDetail.trusttype` — device trust (empty = unregistered)
- `Vendor.deviceDetail.browser` — browser string
- `user_agent.original` — full user agent

### Audit Logs
```
#Vendor="microsoft" #event.module="entraid" #event.dataset="entraid.audit"
```

**Key fields:**
- `Vendor.operationName` — operation (e.g., "Disable account", "Add member to group")
- `Vendor.properties.initiatedBy.user.userPrincipalName` — actor
- `Vendor.properties.targetResources[0].userPrincipalName` — target user
- `Vendor.initiatedBy.app.displayName` — initiating application

## Important Notes

- **Third-party alerts** (`thirdparty:` prefix) are NOT tunable in NGSIEM
- **Always coalesce** dual-schema fields (Graph API vs EntraID parser produce different field paths)
- **Repo filter**: Always include all repos: `(#repo="microsoft_graphapi" OR #repo="3pi_microsoft_entra_id" OR #repo="fcs_csp_events")`
- **Exclude XDR repo**: Add `#repo!="xdr*"` to avoid indicator repo noise
- **Dataset filter**: Use regex `#event.dataset=/entraid/` to catch both `entraid.signin` and `azure.entraid.signin`

## CrowdStrike Container Sensor Field Schema Reference

### ECS Fargate Container Events
```
#event_simpleName=/Container|Pod|Kubernetes/
```

**Primary event types:**
- `PodInfo` — richest metadata (PodLabels, PodSpec, PodName)
- `OciContainerStarted` / `OciContainerStopped` — lifecycle events
- `OciContainerTelemetry` / `OciContainerHeartbeat` — periodic events

**Task identity (from PodName / ComputerName):**
- `PodName` — ECS task ARN: `arn:aws:ecs:{region}:{account}:task/{cluster}/{task-id}`
- `ComputerName` — same as PodName for Fargate
- Extract account/cluster: `regex("(?P<account>\d+):task/(?P<cluster>[^/]+)/", field=PodName)`

**PodLabels (pipe-delimited key:value pairs on PodInfo):**
- `com.amazonaws.ecs.container-name` — container name within task def
- `com.amazonaws.ecs.task-definition-family` — **real service identifier** (NOT container-name)
- `com.amazonaws.ecs.task-definition-version` — revision number
- `com.amazonaws.ecs.cluster` — full cluster ARN
- `com.amazonaws.ecs.task-arn` — full task ARN
- Extract pattern: `regex("com.amazonaws.ecs.container-name:(?P<container_name>[^\|]+)", field=PodLabels)`

**PodSpec (JSON on PodInfo):**
- `containers[].name` — container name
- `containers[].image` — ECR image URI with tag
- `containers[].imageDigest` — SHA256 digest

**Sensor metadata:**
- `CloudService=4` — Fargate indicator
- `product_cwpp=true` — Cloud Workload Protection
- `aid` — unique per ephemeral Fargate task

**Fields NOT populated for Fargate (Kubernetes-only):**
- `ImageName`, `Namespace`, `ClusterName`, `NodeName`, `ContainerName` (on OciContainer* events)

## AWS CloudTrail Field Schema Reference

### Base Filter
```
(#repo="cloudtrail" OR #repo="fcs_csp_events") #Vendor="aws" #repo!="xdr*"
```

**Event identification:**
- `event.provider` — AWS service (e.g., `ec2.amazonaws.com`, `rds.amazonaws.com`, `iam.amazonaws.com`, `signin.amazonaws.com`)
- `event.action` — API action (e.g., `AuthorizeSecurityGroupIngress`, `RestoreDBInstanceFromDBSnapshot`)
- `#event.outcome` — "success" or "failure"

**Actor identity:**
- `Vendor.userIdentity.arn` — full ARN of the actor
- `Vendor.userIdentity.type` — "IAMUser", "AssumedRole", "Root", "FederatedUser"
- `Vendor.userIdentity.principalId` — principal ID

**Cloud context:**
- `cloud.account.id` — AWS account ID
- `cloud.region` — AWS region
- `source.ip` — source IP of the API call
- `user_agent.original` — user agent (identifies Terraform, CLI, Console, SDKs)

**Request/Response (varies by service):**
- `Vendor.requestParameters.*` — API request parameters (e.g., `groupId`, `dBInstanceIdentifier`)
- `Vendor.responseElements.*` — API response elements
