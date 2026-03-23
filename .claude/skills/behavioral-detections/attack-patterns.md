# MITRE ATT&CK-Aligned Attack Patterns

This document provides behavioral detection patterns aligned with MITRE ATT&CK tactics and techniques. Each pattern is designed for the `correlate()` function to detect multi-stage attacks.

## Attack Chain Framework

### Typical Attack Progression

```
[Reconnaissance] → [Initial Access] → [Execution] → [Persistence] → [Privilege Escalation] → [Defense Evasion] → [Credential Access] → [Lateral Movement] → [Collection] → [Exfiltration]
```

Not all attacks follow every stage. Design behavioral rules around the stages most relevant to your threat model.

---

## Pattern: Credential Access → Privilege Escalation

**MITRE**: TA0006 (Credential Access) → TA0004 (Privilege Escalation)

**Attack Flow**: Brute force credentials → Access gained → Escalate privileges

```cql
correlate(
  BruteForce: {
    event.outcome="failure"
    event.action=/UserLogon|Sign-in|ConsoleLogin/
  },
  SuccessfulAccess: {
    event.outcome="success"
    event.action=/UserLogon|Sign-in|ConsoleLogin/
    | user.email <=> BruteForce.user.email
  },
  PrivilegeEscalation: {
    event.action=/AttachUserPolicy|AddMemberToRole|Add.*admin/i
    | user.email <=> BruteForce.user.email
  },
  sequence=true,
  within=4h,
  globalConstraints=[user.email]
)
| case {
    PrivilegeEscalation.event.action=/admin/i | _Severity := "Critical" ;
    * | _Severity := "High" ;
}
```

---

## Pattern: Reconnaissance → Initial Access → Persistence

**MITRE**: TA0043 (Reconnaissance) → TA0001 (Initial Access) → TA0003 (Persistence)

**Attack Flow**: Enumerate resources → Gain access → Establish persistence

```cql
correlate(
  Recon: {
    #Vendor="aws"
    event.action=~in(values=[
      "DescribeInstances",
      "ListBuckets",
      "GetAccountAuthorizationDetails",
      "ListUsers",
      "ListRoles"
    ])
  },
  InitialAccess: {
    #Vendor="aws"
    event.action=~in(values=["ConsoleLogin", "AssumeRole"])
    event.outcome="success"
    | Vendor.userIdentity.arn <=> Recon.Vendor.userIdentity.arn
  },
  Persistence: {
    #Vendor="aws"
    event.action=~in(values=[
      "CreateUser",
      "CreateAccessKey",
      "CreateLoginProfile",
      "PutRolePolicy"
    ])
    | Vendor.userIdentity.arn <=> Recon.Vendor.userIdentity.arn
  },
  sequence=true,
  within=2h,
  globalConstraints=[Vendor.userIdentity.arn]
)
```

---

## Pattern: Defense Evasion → Exfiltration

**MITRE**: TA0005 (Defense Evasion) → TA0010 (Exfiltration)

**Attack Flow**: Disable logging/security → Exfiltrate data

```cql
correlate(
  DisableSecurity: {
    #Vendor="aws"
    event.action=~in(values=[
      "StopLogging",
      "DeleteTrail",
      "PutBucketPolicy",
      "DeleteFlowLogs",
      "DisableAlarmActions"
    ])
  },
  DataAccess: {
    #Vendor="aws"
    event.action=~in(values=[
      "GetObject",
      "CopyObject",
      "SelectObjectContent"
    ])
    | Vendor.userIdentity.arn <=> DisableSecurity.Vendor.userIdentity.arn
  },
  sequence=true,
  within=1h,
  globalConstraints=[Vendor.userIdentity.arn]
)
| _Severity := "Critical"
```

---

## Pattern: Collection → Exfiltration

**MITRE**: TA0009 (Collection) → TA0010 (Exfiltration)

**Attack Flow**: Stage data → Transfer out

```cql
correlate(
  DataCollection: {
    event.action=/FileDownloaded|GetObject|Copy/
    | groupBy([user.email], function=[
        total_bytes := sum(response.bytes),
        file_count := count()
    ])
    | test(total_bytes > 100000000)  // 100MB threshold
  },
  ExfilIndicator: {
    // Unusual destination or method
    event.action=/PutObject|Upload|Sync/
    Vendor.requestParameters.bucketName!=/internal|corp|prod/i
    | user.email <=> DataCollection.user.email
  },
  sequence=true,
  within=4h,
  globalConstraints=[user.email]
)
```

---

## Pattern: Lateral Movement Chain

**MITRE**: TA0008 (Lateral Movement)

**Attack Flow**: Compromise one system → Move to another

```cql
correlate(
  InitialCompromise: {
    #event_simpleName=~in(values=["ProcessRollup2", "SuspiciousActivity"])
    SeverityName=/High|Critical/
  },
  LateralAttempt: {
    event.action=~in(values=["AssumeRole", "GetSessionToken"])
    | cloud.account.id <=> InitialCompromise.cloud.account.id
  },
  CrossAccountAccess: {
    #Vendor="aws"
    Vendor.userIdentity.type="AssumedRole"
    // Different target account than source
    | Vendor.userIdentity.arn <=> LateralAttempt.Vendor.userIdentity.arn
  },
  sequence=true,
  within=2h
)
```

---

## Pattern: Identity Compromise Chain

**Attack Flow**: Phishing consent → Token abuse → Data access

```cql
correlate(
  SuspiciousConsent: {
    #event.module="entra_id"
    event.action="Consent to application"
    azure.auditlogs.properties.additional_details.ConsentType="AllPrincipals"
  },
  TokenAcquisition: {
    #event.module="entra_id"
    event.action=/GetAccessToken|AcquireToken/
    | user.email <=> SuspiciousConsent.user.email
  },
  SensitiveAccess: {
    #event.module="entra_id"
    event.action=/ReadMail|ReadFiles|AccessTeams/
    | user.email <=> SuspiciousConsent.user.email
  },
  sequence=true,
  within=24h,
  globalConstraints=[user.email]
)
```

---

## Pattern: Insider Threat - Resignation to Exfil

**Attack Flow**: Access HR system → Mass download → External transfer

```cql
correlate(
  HRAccess: {
    // Access to resignation/termination related systems
    event.action=/ViewProfile|AccessHRIS/
    AppDisplayName=/Workday|BambooHR|HR platform/
  },
  MassDownload: {
    event.action=/FileDownloaded|Download/
    | user.email <=> HRAccess.user.email
    | groupBy([user.email], function=[file_count := count()])
    | test(file_count > 50)
  },
  ExternalTransfer: {
    // USB, personal cloud, email attachment
    event.action=/FileWritten|Upload|SendMail/
    destination=/removable|personal|gmail|outlook/i
    | user.email <=> HRAccess.user.email
  },
  sequence=true,
  within=72h,
  globalConstraints=[user.email]
)
```

---

## Cross-Source Correlation Patterns

### Endpoint → Cloud

Detect when endpoint compromise leads to cloud resource abuse:

```cql
correlate(
  EndpointAlert: {
    #event_simpleName="EPPDetectionSummaryEvent"
    SeverityName=/High|Critical/
  },
  CloudActivity: {
    #Vendor="aws"
    event.action=/Create|Delete|Modify|Put/
    | user.name <=> EndpointAlert.UserName
  },
  within=4h
)
```

### Identity → Cloud → Endpoint

Track compromise across identity, cloud, and endpoint:

```cql
correlate(
  IdentityCompromise: {
    #event.module="entra_id"
    event.action=/RiskySignIn|UnusualSignIn/
  },
  CloudAccess: {
    #Vendor="aws"
    event.action!=/Read|Describe|List|Get/
    | user.email <=> IdentityCompromise.user.email
  },
  EndpointAccess: {
    #event_simpleName="UserLogon"
    | UserPrincipalName <=> IdentityCompromise.user.email
  },
  sequence=true,
  within=24h,
  globalConstraints=[user.email]
)
```

### Network → Identity → Endpoint (Heterogeneous Keys)

Correlate a SASE network session to an EntraID sign-in via email, then pivot to a Falcon
endpoint event via external IP. Each pair uses a **different** correlation key — the
constellation is held together by the SASE anchor event.

**Key insight**: `sase→entraid` links by `user.email`; `sase→falcon` links by `client.ip`.
There is no single field shared by all three sources.

```cql
correlate(
  // Step 1: SASE network session establishes both email and external IP context
  sase: {
    #Vendor="sase"
    | $sase_enrich_user_identity()
  } include: [user.email, client.ip],

  // Step 2: EntraID sign-in for the same user (email is the join key here)
  entraid: {
    #repo=microsoft_graphapi
    | $entraid_enrich_user_identity()
    | user.name <=> sase.user.email
  } include: [user.email, source.ip, event.action],

  // Step 3: Falcon endpoint activity from the same external IP (IP is the join key here)
  falcon: {
    #event_simpleName=NetworkConnectIP4
    | aip <=> sase.client.ip
  } include: [ComputerName, aip, FileName],

  sequence=false, within=60m
)
| table([sase.user.email, sase.client.ip, entraid.event.action, falcon.ComputerName, falcon.FileName])
```

**When to use**: Anomaly hunting — correlating user identity (email), network presence (IP),
and endpoint telemetry across three separate vendors where no single field exists on all three.
Tune by adding `entraid.source.ip != sase.client.ip` to flag IP mismatches between sources.

---

## Pattern: Windows Discovery Chain (TA0007)

**MITRE**: TA0007 (Discovery)

**Attack Flow**: Attacker runs multiple Windows enumeration tools in quick succession using
raw process telemetry rather than detection alerts. Useful for catching activity that
hasn't triggered a CrowdStrike alert.

**When to use raw `ProcessRollup2` vs detection events**: Use `ProcessRollup2` when you want
to catch enumeration activity that is individually benign but suspicious in combination.
Use `EPPDetectionSummaryEvent` when chaining already-alerted activity into compound cases.

```cql
correlate(
  // whoami — user context enumeration
  whoami: {
    #event_simpleName=ProcessRollup2 event_platform=Win
    FileName="whoami.exe"
  } include: [aid, ComputerName, FileName, UserName],

  // net / net1 — local group and session enumeration
  net: {
    #event_simpleName=ProcessRollup2 event_platform=Win
    FileName=/^net1?\.exe$/
    | aid <=> whoami.aid
  } include: [aid, ComputerName, FileName, CommandLine],

  // systeminfo — full system profile enumeration
  systeminfo: {
    #event_simpleName=ProcessRollup2 event_platform=Win
    FileName="systeminfo.exe"
    | aid <=> net.aid
  } include: [aid, ComputerName, FileName],

  sequence=false, within=5m
)
| table([
    whoami.ComputerName,
    whoami.UserName,
    whoami.FileName,
    net.FileName,
    net.CommandLine,
    systeminfo.FileName
])
```

**Extend the chain**: Add `nltest`, `ipconfig`, `tasklist`, or `arp` as additional queries
to catch broader triage/enumeration toolkits. Use `sequence=true` if you want to enforce
execution order (e.g., whoami always before systeminfo).

---

## Time Window Guidelines

| Pattern Type | Recommended `within` | Rationale |
|--------------|---------------------|-----------|
| Brute force → success | 15-30m | Fast attacks |
| Privilege escalation | 1-2h | Methodical escalation |
| Defense evasion → exfil | 1-4h | Quick after disabling controls |
| Collection → exfil | 4-24h | Data staging takes time |
| Insider threat | 24-72h | Slow, deliberate actions |
| APT multi-stage | Multiple rules | Too long for single rule |

---

## Severity Assignment Framework

| Pattern Characteristics | Severity | Rationale |
|-------------------------|----------|-----------|
| Involves root/admin + external access | Critical (90) | Highest risk |
| Privilege escalation + persistence | High (70) | Attack progression |
| Unusual geo + sensitive action | High (70) | Possible compromise |
| Multiple failed → success | Medium (50) | Potential brute force |
| Audit anomaly | Low (30) | Investigate but low urgency |

---

## Template: Complete Attack Chain Detection

```yaml
name: "Behavioral - [Attack Pattern Name]"
resource_id: behavioral_[pattern_id]
description: |
  Detects [attack description].

  Attack Pattern:
  1. [Stage 1 description]
  2. [Stage 2 description]
  3. [Stage 3 description]

  MITRE ATT&CK:
  - [Tactic/Technique]

severity: [5-90]
status: active
tactic: TA00XX
technique: T1XXX
search:
  filter: |
    correlate(
      Stage1: {
        [filter1]
      },
      Stage2: {
        [filter2]
        | [correlation_key] <=> Stage1.[correlation_key]
      },
      Stage3: {
        [filter3]
        | [correlation_key] <=> Stage1.[correlation_key]
      },
      sequence=true,
      within=[time_window],
      globalConstraints=[[shared_fields]]
    )
    | [enrichment]
    | [severity_assignment]
  lookback: [lookback > within]
  trigger_mode: summary
  outcome: detection
operation:
  schedule:
    definition: '@every [frequency]'
```