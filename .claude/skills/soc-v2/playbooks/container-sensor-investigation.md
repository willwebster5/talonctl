# Playbook: Container Sensor Investigation (ECS Fargate)

**When to use:**
- Investigating container sensor count increases or decreases
- New container/ECS Fargate deployments appearing in Falcon telemetry
- Understanding container workload identity (which services, which accounts)
- Troubleshooting container sensor health or coverage gaps

**Source:** CrowdStrike Falcon container sensor (CWPP) telemetry — native events, not CloudTrail

**Tunable in NGSIEM:** N/A — this is an operational investigation playbook, not alert triage

## Key Event Types

| Event | Purpose | Key Fields |
|-------|---------|------------|
| `PodInfo` | Richest data — contains PodLabels (ECS metadata) and PodSpec (image details) | PodName, PodLabels, PodSpec, CloudService |
| `OciContainerStarted` | Container start events | ComputerName (= task ARN), aid |
| `OciContainerStopped` | Container stop events | ComputerName, aid |
| `OciContainerTelemetry` | Periodic telemetry | aid |
| `OciContainerHeartbeat` | Sensor heartbeat | aid |

**Important:** `PodInfo` is the primary event for identification. `OciContainerStarted` is best for counting starts and trending volume. Other OciContainer events have minimal metadata for Fargate.

## ECS Fargate Field Reference

### PodName / ComputerName
ECS task ARN format: `arn:aws:ecs:{region}:{account}:task/{cluster}/{task-id}`

Extract account and cluster:
```cql
| regex("(?P<account>\d+):task/(?P<cluster>[^/]+)/", field=PodName)
```

### PodLabels (pipe-delimited, URL-encoded key:value pairs)
Contains ECS Docker labels. Key labels:

| Label | What It Is | Extraction Pattern |
|-------|-----------|-------------------|
| `com.amazonaws.ecs.container-name` | Container name within task definition | `regex("com.amazonaws.ecs.container-name:(?P<container_name>[^\|]+)", field=PodLabels)` |
| `com.amazonaws.ecs.task-definition-family` | **ECS service/task def name** (most useful identifier) | `regex("com.amazonaws.ecs.task-definition-family:(?P<task_family>[^\|]+)", field=PodLabels)` |
| `com.amazonaws.ecs.task-definition-version` | Task def revision number | `regex("com.amazonaws.ecs.task-definition-version:(?P<task_version>[^\|]+)", field=PodLabels)` |
| `com.amazonaws.ecs.cluster` | Full cluster ARN | `regex("com.amazonaws.ecs.cluster:(?P<cluster_arn>[^\|]+)", field=PodLabels)` |
| `com.amazonaws.ecs.task-arn` | Full task ARN | `regex("com.amazonaws.ecs.task-arn:(?P<task_arn>[^\|]+)", field=PodLabels)` |

**Critical:** Container name (e.g., "worker") is NOT the ECS service name. Always extract `task-definition-family` for the real service identifier (e.g., "prod-app-worker").

### PodSpec (JSON)
Contains container image details:
- `containers[].name` — container name
- `containers[].image` — full ECR image URI with tag/digest
- `containers[].imageDigest` — SHA256 digest

### Other Key Fields
- `CloudService=4` — indicates Fargate
- `product_cwpp=true` — Cloud Workload Protection (container sensor)
- `AgentVersion` — sensor version (e.g., `7.33.7205.0`)
- `aid` — unique per ephemeral Fargate task (each task = new AID)

## Investigation Queries

### 1. Discover Container Event Types (scope the increase)

What container event types exist and at what volume?

```cql
#event_simpleName=/Container|Pod|Kubernetes/
| groupBy([#event_simpleName], function=[count()])
| sort(_count, order=desc)
```
**Time range:** 1d

### 2. Container Start Trend (7-day baseline)

Daily container start volume to identify when changes began.

```cql
#event_simpleName=OciContainerStarted
| timechart(span=1d, function=count())
```
**Time range:** 7d

### 3. Container Name Breakdown with Unique Sensor Counts

Which containers have sensors and how many unique AIDs each?

```cql
#event_simpleName=PodInfo
| regex("com.amazonaws.ecs.container-name:(?P<container_name>[^\|]+)", field=PodLabels)
| groupBy([container_name], function=[count(aid, distinct=true, as=unique_sensors)])
| sort(unique_sensors, order=desc)
```
**Time range:** 1d

### 4. Account and Cluster Breakdown

Which AWS accounts and ECS clusters are generating container events?

```cql
#event_simpleName=PodInfo
| regex("(?P<account>\d+):task/(?P<cluster>[^/]+)/", field=PodName)
| groupBy([account, cluster], function=[count(), count(aid, distinct=true, as=unique_sensors)])
| sort(unique_sensors, order=desc)
```
**Time range:** 1d

### 5. Task Definition Family Extraction (key service identifier)

Map container names to their ECS task definition families.

```cql
#event_simpleName=PodInfo
| regex("com.amazonaws.ecs.container-name:(?P<container_name>[^\|]+)", field=PodLabels)
| regex("com.amazonaws.ecs.task-definition-family:(?P<task_family>[^\|]+)", field=PodLabels)
| groupBy([task_family, container_name], function=[count(aid, distinct=true, as=unique_sensors)])
| sort(unique_sensors, order=desc)
```
**Time range:** 1d

### 6. Image/PodSpec Analysis

What container images are deployed?

```cql
#event_simpleName=PodInfo
| regex("com.amazonaws.ecs.container-name:{{container_name}}", field=PodLabels)
| groupBy([PodSpec], function=[count()])
| sort(_count, order=desc)
```
**Time range:** 1d

### 7. Unique Sensor Trend for Specific Container (daily)

Track when sensors for a specific container name first appeared.

```cql
#event_simpleName=PodInfo
| regex("com.amazonaws.ecs.container-name:{{container_name}}[|]", field=PodLabels)
| timechart(span=1d, function=[count(aid, distinct=true, as=unique_sensors)])
```
**Time range:** 7d

**Note:** The `[|]` after the container name ensures exact match (PodLabels are pipe-delimited).

### 8. Narrow to Specific Account/Cluster

Filter container events to a specific account and cluster.

```cql
#event_simpleName=PodInfo
| regex("com.amazonaws.ecs.container-name:(?P<container_name>[^\|]+)", field=PodLabels)
| regex("(?P<account>\d+):task/(?P<cluster>[^/]+)/", field=PodName)
| account="{{account_id}}"
| cluster="{{cluster_name}}"
| groupBy([container_name], function=[count(aid, distinct=true, as=unique_sensors)])
| sort(unique_sensors, order=desc)
```
**Time range:** 1d

### 9. Cross-Reference CloudTrail for ECS Deployment Activity

Check if the container changes correlate with ECS management API calls.

```cql
(#repo="cloudtrail" OR #repo="fcs_csp_events") #Vendor="aws" #repo!="xdr*"
| event.action=/RunTask|UpdateService|CreateService|RegisterTaskDefinition/
| groupBy([event.action, cloud.account.id], function=[count()])
| sort(_count, order=desc)
```
**Time range:** 3d

### 10. CloudTrail RunTask Trend (compare with sensor trend)

Is the task churn increasing, or is this a new sensor deployment on existing tasks?

```cql
(#repo="cloudtrail" OR #repo="fcs_csp_events") #Vendor="aws" #repo!="xdr*"
| event.action=RunTask
| timechart(span=1d, function=count())
```
**Time range:** 7d

**Key insight:** If RunTask volume is stable but sensor count spiked, this is a new sensor rollout (sidecar added to existing tasks). If both spiked, this is a scaling event.

### 11. Agent Version Breakdown

Which sensor versions are running on container hosts?

```cql
#event_simpleName=AgentOnline event_platform=Lin
| groupBy([AgentVersion], function=[count(), count(hostname, distinct=true, as=unique_hosts)])
| sort(_count, order=desc)
```
**Time range:** 1d

## Triage Checklist

1. **Is this a new sensor deployment?** Check Query 7 — did sensors for a container name jump from 0 to N? Compare with CloudTrail RunTask trend (Query 10) — stable RunTask + new sensors = sidecar rollout.
2. **Is this a scaling event?** Both sensor count AND CloudTrail RunTask volume increasing? This is auto-scaling or a deployment spike.
3. **Is this deployment churn?** High unique sensors with low long-lived sensors? Check task definition version (Query 5) — multiple versions in short succession indicates active iteration (devs pushing changes).
4. **Which team owns this?** Use the task-definition-family (Query 5) to identify the application, then cross-reference `environmental-context.md` for account/app ownership.
5. **Is sensor coverage expected?** Cross-reference with known Falcon container sensor deployments in `environmental-context.md`. If a cluster/service is listed as having sensors, the activity is expected.

## Known Pitfalls

- **Kubernetes-only fields are empty for Fargate**: `ImageName`, `Namespace`, `ClusterName`, `NodeName`, `ContainerName` (on OciContainer* events) are not populated. Use `PodLabels` from `PodInfo` events instead.
- **Don't chain groupBy then timechart**: `groupBy() | timechart()` returns 0 results. Use one or the other.
- **selectFields() may fail on some container fields**: Use `head()` to inspect raw events, then `groupBy()` or `regex()` to extract.
- **CloudTrail nested requestParameters**: `groupBy([requestParameters.taskDefinition])` may return 0 results for CloudTrail. Use simpler groupBy keys or `head()` to inspect raw events.
- **Container name != ECS service name**: The `container-name` label is the container name within the task definition (e.g., "worker"), NOT the ECS service name. Always extract `task-definition-family` for the real identifier (e.g., "prod-app-worker").

## ECS Fargate Baseline (as of March 2026)

Reference `environmental-context.md` for current account/cluster/application mappings. Key baselines:
- `prod-app-worker` (account `333333333333`): ~1,500 unique sensors/day — this is normal churn
- `888888888888` platform services: ~20-80 sensors/day depending on service
- `555555555555` staging: ~100 sensors/day
