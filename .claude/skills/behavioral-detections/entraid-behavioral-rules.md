# EntraID Behavioral Detection Rules

Production-ready behavioral detection patterns for Microsoft Entra ID (Azure AD) events using `correlate()`.

## Brute Force → Successful Login

**Detects**: Multiple failed logins followed by successful authentication

**MITRE**: T1110 (Brute Force), T1078 (Valid Accounts)

```cql
correlate(
  FailedAttempts: {
    #event.module="entra_id"
    event.outcome="failure"
    event.action=/UserLogon|Sign-in/
  },
  SuccessfulLogin: {
    #event.module="entra_id"
    event.outcome="success"
    event.action=/UserLogon|Sign-in/
    | user.email <=> FailedAttempts.user.email
  } include: [source.ip, source.geo.country_name, user_agent.original],
  sequence=true,
  within=30m,
  globalConstraints=[user.email]
)
| groupBy([SuccessfulLogin.user.email, FailedAttempts.source.ip],
    function=[
      failed_count := count(FailedAttempts.@id, distinct=true),
      success_count := count(SuccessfulLogin.@id, distinct=true)
    ])
| test(failed_count >= 5)
| case {
    SuccessfulLogin.source.geo.country_name!="United States"
        | _Severity := 90 | _Risk := "Critical" ;
    test(failed_count >= 20)
        | _Severity := 70 | _Risk := "High" ;
    * | _Severity := 50 | _Risk := "Medium" ;
}
```

### Complete YAML Template

```yaml
name: "EntraID - Brute Force Followed by Success"
resource_id: entraid_brute_force_success
description: |
  Detects brute force attack pattern:
  1. Multiple failed login attempts (5+)
  2. Followed by successful authentication

  This indicates potential credential compromise through
  brute force or credential stuffing attack.

  MITRE ATT&CK:
  - T1110: Brute Force
  - T1078: Valid Accounts

severity: 70
status: active
tactic: TA0006
technique: T1110
search:
  filter: |
    correlate(
      FailedAttempts: {
        #event.module="entra_id"
        event.outcome="failure"
        event.action=/UserLogon|Sign-in/
      },
      SuccessfulLogin: {
        #event.module="entra_id"
        event.outcome="success"
        event.action=/UserLogon|Sign-in/
        | user.email <=> FailedAttempts.user.email
      } include: [source.ip, source.geo.country_name],
      sequence=true,
      within=30m,
      globalConstraints=[user.email]
    )
    | groupBy([SuccessfulLogin.user.email],
        function=[failed_count := count(FailedAttempts.@id, distinct=true)])
    | test(failed_count >= 5)
  lookback: 1h
  trigger_mode: summary
  outcome: detection
operation:
  schedule:
    definition: '@every 30m'
```

---

## MFA Fatigue Attack → Success

**Detects**: Multiple MFA challenges → User approves (fatigue attack)

**MITRE**: T1621 (Multi-Factor Authentication Request Generation)

```cql
correlate(
  MFAChallenges: {
    #event.module="entra_id"
    event.action=/MFA challenge|StrongAuthenticationRequired/
    event.outcome="failure"
  },
  MFAApproved: {
    #event.module="entra_id"
    event.action=/MFA challenge|StrongAuthenticationCompleted/
    event.outcome="success"
    | user.email <=> MFAChallenges.user.email
  },
  sequence=true,
  within=15m,  // Short window for fatigue attacks
  globalConstraints=[user.email]
)
| groupBy([MFAApproved.user.email],
    function=[challenge_count := count(MFAChallenges.@id, distinct=true)])
| test(challenge_count >= 10)  // 10+ challenges before success
| _Severity := 90
| _Risk := "Critical"
| _Reason := "Potential MFA fatigue attack"
```

---

## Password Spray Across Multiple Accounts

**Detects**: Failed logins across many accounts from same source

**MITRE**: T1110.003 (Password Spraying)

```cql
correlate(
  SprayAttempts: {
    #event.module="entra_id"
    event.outcome="failure"
    event.action=/UserLogon|Sign-in/
    azure.signinlogs.properties.status.errorCode=~in(values=[
      "50126",  // Invalid username or password
      "50053"   // Account locked
    ])
    | groupBy([source.ip],
        function=[
          unique_accounts := count(user.email, distinct=true),
          total_attempts := count()
        ])
    | test(unique_accounts >= 10)  // 10+ different accounts
  },
  SuccessfulSpray: {
    #event.module="entra_id"
    event.outcome="success"
    event.action=/UserLogon|Sign-in/
    | source.ip <=> SprayAttempts.source.ip
  },
  sequence=true,
  within=1h,
  globalConstraints=[source.ip]
)
| _Severity := 90
| _Risk := "Critical"
| _Reason := format("Password spray: %d accounts targeted, one succeeded", field=[SprayAttempts.unique_accounts])
```

---

## Impossible Travel → Sensitive Action

**Detects**: Login from distant location → Administrative action

**MITRE**: T1078 (Valid Accounts), T1098 (Account Manipulation)

```cql
correlate(
  InitialLogin: {
    #event.module="entra_id"
    event.outcome="success"
    event.action=/UserLogon|Sign-in/
  } include: [source.ip, source.geo.country_name, source.geo.city_name],
  DistantLogin: {
    #event.module="entra_id"
    event.outcome="success"
    event.action=/UserLogon|Sign-in/
    | user.email <=> InitialLogin.user.email
    // Different country within short window = impossible travel
  } include: [source.ip, source.geo.country_name, source.geo.city_name],
  AdminAction: {
    #event.module="entra_id"
    event.action=/Add member to role|Update user|Reset password/
    | user.email <=> InitialLogin.user.email
  },
  sequence=true,
  within=4h,
  globalConstraints=[user.email]
)
| test(InitialLogin.source.geo.country_name != DistantLogin.source.geo.country_name)
| _Severity := 70
| _Risk := "High"
| _Reason := format("Impossible travel: %s → %s → admin action",
    field=[InitialLogin.source.geo.country_name, DistantLogin.source.geo.country_name])
```

---

## OAuth Consent Phishing → Token Abuse

**Detects**: Risky app consent → API access with granted permissions

**MITRE**: T1528 (Steal Application Access Token)

```cql
correlate(
  SuspiciousConsent: {
    #event.module="entra_id"
    event.action="Consent to application"
    // High-risk permissions
    azure.auditlogs.properties.additional_details.ConsentType=~in(values=[
      "AllPrincipals",
      "Principal"
    ])
    azure.auditlogs.properties.target_resources.modifiedProperties.newValue=/Mail|Files|Directory/
  },
  TokenAcquisition: {
    #event.module="entra_id"
    event.action=/GetAccessToken|OAuth2/
    | user.email <=> SuspiciousConsent.user.email
  },
  SensitiveAccess: {
    #event.module="m365"
    event.action=/MailItemsAccessed|FileAccessed|MessageRead/
    | user.email <=> SuspiciousConsent.user.email
  },
  sequence=true,
  within=24h,
  globalConstraints=[user.email]
)
| _Severity := 90
| _Risk := "Critical"
```

---

## Privilege Escalation: Role Assignment Chain

**Detects**: User added to role → Then adds others to privileged roles

**MITRE**: T1098.003 (Additional Cloud Roles)

```cql
correlate(
  InitialRoleGrant: {
    #event.module="entra_id"
    event.action=/Add member to role|Add eligible member/
    azure.auditlogs.properties.target_resources.modifiedProperties.newValue=/Admin/
  },
  SubsequentGrants: {
    #event.module="entra_id"
    event.action=/Add member to role|Add eligible member/
    // The user who received the role is now granting roles
    | azure.auditlogs.properties.initiated_by.user.userPrincipalName <=> InitialRoleGrant.azure.auditlogs.properties.target_resources.userPrincipalName
  },
  sequence=true,
  within=4h
)
| _Severity := 70
| _Risk := "High"
| _Reason := "Privilege escalation chain detected"
```

---

## Account Compromise → Email Rule Creation

**Detects**: Unusual login → Mailbox rule created (persistence)

**MITRE**: T1564.008 (Email Hiding Rules)

```cql
correlate(
  UnusualLogin: {
    #event.module="entra_id"
    event.outcome="success"
    event.action=/UserLogon|Sign-in/
    // Flagged as risky by Azure
    azure.signinlogs.properties.riskLevel!="none"
  },
  MailboxRule: {
    #event.module="m365"
    event.action=~in(values=[
      "New-InboxRule",
      "Set-InboxRule",
      "UpdateInboxRules"
    ])
    // Suspicious rule patterns
    Vendor.Parameters=/DeleteMessage|MarkAsRead|MoveToFolder/
    | user.email <=> UnusualLogin.user.email
  },
  sequence=true,
  within=24h,
  globalConstraints=[user.email]
)
| _Severity := 70
| _Risk := "High"
| _Reason := "Risky login followed by mailbox rule creation"
```

---

## Guest User Abuse Pattern

**Detects**: Guest invite → Excessive permission grants

**MITRE**: T1136.003 (Cloud Account)

```cql
correlate(
  GuestInvite: {
    #event.module="entra_id"
    event.action=/Invite external user|Add user/
    azure.auditlogs.properties.target_resources.userType="Guest"
  },
  PermissionGrant: {
    #event.module="entra_id"
    event.action=~in(values=[
      "Add member to role",
      "Add app role assignment to service principal",
      "Add delegated permission grant"
    ])
    | azure.auditlogs.properties.target_resources.userPrincipalName <=> GuestInvite.azure.auditlogs.properties.target_resources.userPrincipalName
  },
  sequence=true,
  within=24h
)
| _Severity := 50
| _Risk := "Medium"
```

---

## Service Principal Abuse

**Detects**: Service principal credential added → Sensitive API calls

**MITRE**: T1098.001 (Additional Cloud Credentials)

```cql
correlate(
  CredentialAdded: {
    #event.module="entra_id"
    event.action=/Add service principal credentials|Update application/
  },
  SensitiveAPICall: {
    #event.module="entra_id"
    // Service principal making directory reads/writes
    event.action=/Get user|Update user|Add member|Graph API/
    azure.auditlogs.properties.initiated_by.app.appId=*
    | azure.auditlogs.properties.initiated_by.app.appId <=> CredentialAdded.azure.auditlogs.properties.target_resources.appId
  },
  sequence=true,
  within=4h
)
| _Severity := 70
| _Risk := "High"
```

---

## Quick Reference: EntraID Event Actions

### Authentication Events
- `UserLogon`, `Sign-in activity`
- `MFA challenge`, `StrongAuthenticationCompleted`

### Privilege Events
- `Add member to role`, `Add eligible member`
- `Add owner to group`, `Add member to group`

### Application Events
- `Consent to application`
- `Add service principal`, `Add service principal credentials`
- `OAuth2 permission grant`

### User Management Events
- `Add user`, `Update user`, `Delete user`
- `Reset password`, `Change password`
- `Invite external user`

### Mailbox Events (M365)
- `New-InboxRule`, `Set-InboxRule`
- `MailItemsAccessed`, `FileAccessed`

---

## Error Codes Reference

Common Azure SignIn error codes for filtering:

| Code | Description | Use Case |
|------|-------------|----------|
| 50126 | Invalid username/password | Brute force detection |
| 50053 | Account locked | Spray detection |
| 50057 | Account disabled | Disabled account access |
| 50076 | MFA required | MFA enforcement |
| 50074 | Strong auth required | Conditional access |
| 53003 | Blocked by conditional access | Policy block |

```cql
// Filter for specific error codes
azure.signinlogs.properties.status.errorCode=~in(values=["50126", "50053"])
```