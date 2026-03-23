  # AWS Behavioral Detection Rules

Production-ready behavioral detection patterns for AWS CloudTrail events using `correlate()`.

## IAM Privilege Escalation Chain

**Detects**: User creation → Admin policy attachment → Credential creation

**MITRE**: T1098 (Account Manipulation), T1078 (Valid Accounts)

```cql
correlate(
  CreateUser: {
    #Vendor="aws"
    event.action="CreateUser"
    #event.outcome="success"
  },
  AttachAdminPolicy: {
    #Vendor="aws"
    event.action="AttachUserPolicy"
    Vendor.requestParameters.policyArn=/AdministratorAccess|PowerUserAccess|IAMFullAccess/
    | Vendor.userIdentity.arn <=> CreateUser.Vendor.userIdentity.arn
    | Vendor.requestParameters.userName <=> CreateUser.Vendor.requestParameters.userName
  },
  CreateCredentials: {
    #Vendor="aws"
    event.action=~in(values=["CreateAccessKey", "CreateLoginProfile"])
    | Vendor.userIdentity.arn <=> CreateUser.Vendor.userIdentity.arn
    | Vendor.requestParameters.userName <=> CreateUser.Vendor.requestParameters.userName
  },
  sequence=true,
  within=2h,
  globalConstraints=[Vendor.userIdentity.arn]
)
| ipLocation(CreateUser.source.ip)
| asn(CreateUser.source.ip)
| case {
    CreateUser.source.ip.country!="United States" | _Severity := 90 | _Risk := "Critical" ;
    * | _Severity := 70 | _Risk := "High" ;
}
| table([
    _Severity,
    _Risk,
    CreateUser.Vendor.userIdentity.arn,
    CreateUser.Vendor.requestParameters.userName,
    AttachAdminPolicy.Vendor.requestParameters.policyArn,
    CreateUser.source.ip,
    CreateUser.source.ip.country
])
```

### Complete YAML Template

```yaml
name: "AWS - IAM Privilege Escalation Chain"
resource_id: aws_iam_privilege_escalation_chain
description: |
  Detects IAM privilege escalation attack pattern:
  1. New IAM user created
  2. Administrative policy attached to new user
  3. Access credentials created for new user

  This pattern indicates potential account takeover or insider threat
  establishing persistent administrative access.

  MITRE ATT&CK:
  - T1098: Account Manipulation
  - T1078: Valid Accounts

severity: 70
status: active
tactic: TA0004
technique: T1098
search:
  filter: |
    correlate(
      CreateUser: {
        #Vendor="aws" event.action="CreateUser" #event.outcome="success"
      },
      AttachAdminPolicy: {
        #Vendor="aws" event.action="AttachUserPolicy"
        Vendor.requestParameters.policyArn=/AdministratorAccess|PowerUserAccess|IAMFullAccess/
        | Vendor.userIdentity.arn <=> CreateUser.Vendor.userIdentity.arn
        | Vendor.requestParameters.userName <=> CreateUser.Vendor.requestParameters.userName
      },
      CreateCredentials: {
        #Vendor="aws" event.action=~in(values=["CreateAccessKey", "CreateLoginProfile"])
        | Vendor.userIdentity.arn <=> CreateUser.Vendor.userIdentity.arn
        | Vendor.requestParameters.userName <=> CreateUser.Vendor.requestParameters.userName
      },
      sequence=true,
      within=2h,
      globalConstraints=[Vendor.userIdentity.arn]
    )
    | ipLocation(CreateUser.source.ip)
  lookback: 4h
  trigger_mode: summary
  outcome: detection
operation:
  schedule:
    definition: '@every 1h'
```

---

## Cross-Account Trust Abuse

**Detects**: Trust policy modification → Cross-account role assumption from new account

**MITRE**: T1550.001 (Use Alternate Authentication Material: Application Access Token)

```cql
correlate(
  TrustPolicyChange: {
    #Vendor="aws"
    event.action=~in(values=["UpdateAssumeRolePolicy", "CreateRole"])
    Vendor.requestParameters.policyDocument=/arn:aws:iam::\d{12}:/
  },
  CrossAccountAssume: {
    #Vendor="aws"
    event.action="AssumeRole"
    #event.outcome="success"
    // Source account different from target account
    | Vendor.recipientAccountId <=> TrustPolicyChange.Vendor.recipientAccountId
  },
  within=4h
)
| $aws_classify_account_trust()
| aws.account_trust_type="external"
| _Severity := 90
```

---

## Console Login After API Recon

**Detects**: API reconnaissance → Console access from different location

**MITRE**: T1078 (Valid Accounts), TA0043 (Reconnaissance)

```cql
correlate(
  APIRecon: {
    #Vendor="aws"
    event.action=~in(values=[
      "DescribeInstances",
      "ListBuckets",
      "GetAccountAuthorizationDetails",
      "ListUsers",
      "ListRoles",
      "DescribeSecurityGroups"
    ])
    Vendor.userIdentity.invokedBy!="amazonaws.com"
  },
  ConsoleLogin: {
    #Vendor="aws"
    event.action="ConsoleLogin"
    #event.outcome="success"
    | Vendor.userIdentity.arn <=> APIRecon.Vendor.userIdentity.arn
  },
  sequence=true,
  within=1h,
  globalConstraints=[Vendor.userIdentity.arn]
)
| ipLocation(APIRecon.source.ip)
| ipLocation(ConsoleLogin.source.ip)
| case {
    // Different source IPs
    test(APIRecon.source.ip != ConsoleLogin.source.ip)
        | _Risk := "High" | _Reason := "Different source IPs" ;
    // Different countries
    test(APIRecon.source.ip.country != ConsoleLogin.source.ip.country)
        | _Risk := "Critical" | _Reason := "Different countries" ;
    * | _Risk := "Medium" | _Reason := "Recon followed by console access" ;
}
```

---

## S3 Data Staging to Exfiltration

**Detects**: Bulk S3 reads → External S3 upload or unusual transfer

**MITRE**: T1530 (Data from Cloud Storage Object), T1537 (Transfer Data to Cloud Account)

```cql
correlate(
  DataStaging: {
    #Vendor="aws"
    event.action="GetObject"
    // Aggregate to detect bulk access
    | groupBy([Vendor.userIdentity.arn, Vendor.requestParameters.bucketName],
        function=[
          object_count := count(),
          total_bytes := sum(Vendor.additionalEventData.bytesTransferredOut)
        ])
    | test(object_count > 100 OR total_bytes > 1000000000)  // 100+ objects or 1GB
  },
  ExfilIndicator: {
    #Vendor="aws"
    event.action=~in(values=["PutObject", "CopyObject"])
    // Different bucket (potential external transfer)
    | Vendor.userIdentity.arn <=> DataStaging.Vendor.userIdentity.arn
    | test(Vendor.requestParameters.bucketName != DataStaging.Vendor.requestParameters.bucketName)
  },
  sequence=true,
  within=4h,
  globalConstraints=[Vendor.userIdentity.arn]
)
```

---

## CloudTrail Tampering Followed by Sensitive Actions

**Detects**: Disable logging → Perform sensitive operations

**MITRE**: T1562.008 (Impair Defenses: Disable Cloud Logs)

```cql
correlate(
  LogTampering: {
    #Vendor="aws"
    event.action=~in(values=[
      "StopLogging",
      "DeleteTrail",
      "UpdateTrail",
      "PutEventSelectors"
    ])
  },
  SensitiveAction: {
    #Vendor="aws"
    event.action=~in(values=[
      "CreateUser",
      "CreateAccessKey",
      "AttachUserPolicy",
      "PutBucketPolicy",
      "DeleteBucket",
      "RunInstances",
      "CreateSecurityGroup"
    ])
    | Vendor.userIdentity.arn <=> LogTampering.Vendor.userIdentity.arn
  },
  sequence=true,
  within=30m,  // Short window - immediate action after disabling
  globalConstraints=[Vendor.userIdentity.arn]
)
| _Severity := 90
| _Risk := "Critical"
| _Reason := "Log tampering followed by sensitive action"
```

---

## EC2 Cryptomining Pattern

**Detects**: Launch many instances → Of specific GPU/compute types

**MITRE**: T1496 (Resource Hijacking)

```cql
correlate(
  InstanceLaunch: {
    #Vendor="aws"
    event.action="RunInstances"
    #event.outcome="success"
    | groupBy([Vendor.userIdentity.arn],
        function=[
          instance_count := count(),
          instance_types := collect([Vendor.requestParameters.instanceType])
        ])
    | test(instance_count >= 5)
  },
  GPUInstances: {
    #Vendor="aws"
    event.action="RunInstances"
    Vendor.requestParameters.instanceType=/p[234]|g[45]|trn|inf/  // GPU/ML instances
    | Vendor.userIdentity.arn <=> InstanceLaunch.Vendor.userIdentity.arn
  },
  within=1h,
  globalConstraints=[Vendor.userIdentity.arn]
)
| $aws_service_account_detector()
| aws.is_service_account=false  // Exclude known automation
| _Severity := 70
```

---

## Root Account Usage After IAM Changes

**Detects**: IAM changes → Root account login (potential lockout attempt)

**MITRE**: T1531 (Account Access Removal)

```cql
correlate(
  IAMChanges: {
    #Vendor="aws"
    event.action=~in(values=[
      "DeleteUser",
      "DeleteAccessKey",
      "UpdateLoginProfile",
      "DeleteLoginProfile",
      "DetachUserPolicy"
    ])
  },
  RootLogin: {
    #Vendor="aws"
    event.action="ConsoleLogin"
    Vendor.userIdentity.type="Root"
    | Vendor.recipientAccountId <=> IAMChanges.Vendor.recipientAccountId
  },
  sequence=true,
  within=30m,
  globalConstraints=[Vendor.recipientAccountId]
)
| _Severity := 90
| _Risk := "Critical"
```

---

## Security Group Open to Internet

**Detects**: Create security group → Add 0.0.0.0/0 rule → Launch instance

**MITRE**: T1190 (Exploit Public-Facing Application)

```cql
correlate(
  CreateSG: {
    #Vendor="aws"
    event.action="CreateSecurityGroup"
  },
  OpenRule: {
    #Vendor="aws"
    event.action=~in(values=["AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress"])
    Vendor.requestParameters.ipPermissions.items.ipRanges.items.cidrIp="0.0.0.0/0"
    | Vendor.userIdentity.arn <=> CreateSG.Vendor.userIdentity.arn
    | Vendor.requestParameters.groupId <=> CreateSG.Vendor.responseElements.groupId
  },
  LaunchInstance: {
    #Vendor="aws"
    event.action="RunInstances"
    | Vendor.userIdentity.arn <=> CreateSG.Vendor.userIdentity.arn
  },
  sequence=true,
  within=1h,
  globalConstraints=[Vendor.userIdentity.arn]
)
| case {
    OpenRule.Vendor.requestParameters.ipPermissions.items.fromPort=~in(values=[22, 3389])
        | _Risk := "Critical" | _Reason := "SSH/RDP exposed to internet" ;
    * | _Risk := "High" | _Reason := "Security group open to internet" ;
}
```

---

## Service Account Filtering

For all AWS behavioral rules, consider adding service account filtering:

```cql
// Add after correlate() output
| $aws_enrich_user_identity()
| $aws_classify_identity_type(include_service_detection="true")
| aws.is_human_identity=true

// Or specific service account exclusions
| $aws_service_account_detector()
| aws.service_account_type!="iac"  // Allow IaC detection
| aws.service_account_type!="monitoring"  // Allow monitoring detection
```

---

## Quick Reference: AWS Event Actions

### Reconnaissance Events
- `DescribeInstances`, `DescribeSecurityGroups`
- `ListBuckets`, `ListUsers`, `ListRoles`
- `GetAccountAuthorizationDetails`

### Privilege Escalation Events
- `CreateUser`, `AttachUserPolicy`, `PutUserPolicy`
- `CreateRole`, `AttachRolePolicy`, `UpdateAssumeRolePolicy`

### Persistence Events
- `CreateAccessKey`, `CreateLoginProfile`
- `CreateUser`, `PutRolePolicy`

### Defense Evasion Events
- `StopLogging`, `DeleteTrail`, `UpdateTrail`
- `DeleteFlowLogs`, `DisableAlarmActions`

### Exfiltration Events
- `GetObject`, `CopyObject`, `PutObject`
- `CreateSnapshot`, `ModifySnapshotAttribute`