# Playbook: EntraID Risky Sign-In & Account Security (NGSIEM)

**Triggers on:** `ngsiem:` composite ID prefix, detection names matching:
- `Microsoft - Entra ID - Risky Sign-in`
- `Microsoft - Entra ID - Risky Sign-in via CLI Tools`
- `Microsoft - Entra ID - Potential Adversary-in-the-Middle Login Sequence`
- `Microsoft - Entra ID - Suspicious SignIns From A Non Registered Device`
- `Microsoft - Entra ID - Account Lockout`
- `Microsoft - Entra ID - Login to Disabled Account`
- `Microsoft - Entra ID - Multifactor Authentication Denied`
- `Microsoft - Entra ID - MFA Fraud Reported by End User`
- `Microsoft - Entra ID - Password Spray Detection by Source IP`
- `Microsoft - Entra ID - Primary Refresh Token Abuse *`
- `Microsoft - Entra ID - Sign-in Failure Due to Conditional Access Requirements Not Met`

**Source:** NGSIEM correlation rules matching EntraID sign-in logs
**Tunable in NGSIEM:** Yes — detection templates in `resources/detections/microsoft/`

## Base Query Filter (copy-paste start)

All EntraID sign-in investigation queries should start with this base:

```cql
(#repo="microsoft_graphapi" OR #repo="3pi_microsoft_entra_id" OR #repo="fcs_csp_events")
#Vendor="microsoft" #event.dataset=/entraid\.signin/ #repo!="xdr*"
| #event.kind="event"
```

## Investigation Queries

### 1. Full Sign-In Detail for a Specific User

Complete sign-in history with risk, CA, device, and app context.

```cql
(#repo="microsoft_graphapi" OR #repo="3pi_microsoft_entra_id" OR #repo="fcs_csp_events")
#Vendor="microsoft" #event.dataset=/entraid\.signin/ #repo!="xdr*"
| #event.kind="event"
| coalesce([user.email, user.full_name], as=_userPrincipalName)
| _userPrincipalName="{{user}}"
| coalesce([Vendor.appDisplayName, Vendor.properties.appDisplayName], as=_appDisplayName)
| coalesce([Vendor.riskLevelDuringSignIn, Vendor.properties.riskLevelDuringSignIn], as=_riskLevel)
| coalesce([Vendor.riskState, Vendor.properties.riskState], as=_riskState)
| coalesce([Vendor.correlationId, Vendor.properties.correlationId], as=_correlationId)
| asn(source.ip)
| table([@timestamp, _userPrincipalName, #event.outcome, error.code, _appDisplayName, source.ip, source.ip.org, source.geo.city_name, source.geo.country_name, _riskLevel, _riskState, Vendor.AuthenticationRequirement, Vendor.conditionalAccessStatus, Vendor.DeviceDetail.trusttype, user_agent.original, _correlationId], limit=50, sortby=@timestamp, order=desc)
```
**Time range:** 7d

### 2. Failed Sign-Ins by Error Code (Password Spray / Lockout Investigation)

Group failed sign-ins by source IP to identify spray patterns.

```cql
(#repo="microsoft_graphapi" OR #repo="3pi_microsoft_entra_id" OR #repo="fcs_csp_events")
#Vendor="microsoft" #event.dataset=/entraid\.signin/ #repo!="xdr*"
| #event.kind="event" #event.outcome="failure"
| array:contains(array="event.category[]", value="authentication")
| error.code =~ in(values=["50053", "50055", "50057", "50126"])
| coalesce([user.email, user.full_name], as=_userPrincipalName)
| coalesce([Vendor.appDisplayName, Vendor.properties.appDisplayName], as=_appDisplayName)
| asn(source.ip)
| groupBy(source.ip, function=[
    count(_userPrincipalName, distinct="true", as=_distinctUsers),
    count(as=total_attempts),
    collect([_userPrincipalName, _appDisplayName, error.code, error.message, source.ip.org, source.geo.city_name, source.geo.country_name])
  ], limit=max)
| sort(_distinctUsers, order=desc)
```
**Time range:** 1h (expand to 24h if needed)

**Error code reference:**
| Code | Meaning |
|------|---------|
| 0 | Success |
| 50053 | Account locked (too many failed attempts, or blocked IP) |
| 50055 | Password expired |
| 50057 | Account disabled |
| 50074 | Strong auth required (MFA challenge) |
| 50097 | Device authentication required |
| 50126 | Invalid username or password |
| 50140 | "Keep me signed in" interrupt |
| 50203 | User hasn't registered authenticator app |
| 53003 | Blocked by Conditional Access |

### 3. Risky Sign-Ins Across All Users (Risk Dashboard)

See all medium/high risk sign-ins in the environment.

```cql
(#repo="microsoft_graphapi" OR #repo="3pi_microsoft_entra_id" OR #repo="fcs_csp_events")
#Vendor="microsoft" #event.dataset=/entraid\.signin/ #repo!="xdr*"
| #event.kind="event"
| coalesce([Vendor.riskLevelDuringSignIn, Vendor.properties.riskLevelDuringSignIn], as=_riskLevel)
| _riskLevel =~ in(values=["medium", "high"])
| coalesce([user.email, user.full_name], as=_userPrincipalName)
| coalesce([Vendor.riskState, Vendor.properties.riskState], as=_riskState)
| coalesce([Vendor.appDisplayName, Vendor.properties.appDisplayName], as=_appDisplayName)
| asn(source.ip)
| table([@timestamp, _userPrincipalName, #event.outcome, _riskLevel, _riskState, _appDisplayName, source.ip, source.ip.org, source.geo.country_name, user_agent.original], limit=50, sortby=@timestamp, order=desc)
```
**Time range:** 24h

### 4. AiTM / Adversary-in-the-Middle Session Analysis

Correlate sign-in events by correlation ID to detect the fail-then-succeed pattern.

```cql
(#repo="microsoft_graphapi" OR #repo="3pi_microsoft_entra_id" OR #repo="fcs_csp_events")
#Vendor="microsoft" #event.dataset=/entraid\.signin/ #repo!="xdr*"
| coalesce([user.email, user.full_name], as=_userPrincipalName)
| _userPrincipalName="{{user}}"
| Vendor.appDisplayName="OfficeHome" OR Vendor.properties.appDisplayName="OfficeHome" OR Vendor.appDisplayName="Office 365 Exchange Online" OR Vendor.properties.appDisplayName="Office 365 Exchange Online"
| coalesce([Vendor.correlationId, Vendor.properties.correlationId], as=_correlationId)
| coalesce([Vendor.riskLevelDuringSignIn, Vendor.properties.riskLevelDuringSignIn], as=_riskLevel)
| coalesce([Vendor.riskState, Vendor.properties.riskState], as=_riskState)
| asn(source.ip)
| groupBy([_correlationId, _userPrincipalName], function=[
    collect([error.code, #event.outcome, source.ip, source.ip.org, _riskLevel, _riskState, user_agent.original])
  ], limit=max)
```
**Time range:** 24h

**AiTM indicators:** A single `_correlationId` with BOTH `error.code=0` (success) AND failure codes like `50074`, `53003`, `50126`, combined with medium/high risk level.

### 5. CLI Tool Sign-Ins (Privilege Abuse Investigation)

Detect sign-ins via Azure PowerShell, Graph SDK, or Azure CLI — common in post-compromise.

```cql
(#repo="microsoft_graphapi" OR #repo="3pi_microsoft_entra_id" OR #repo="fcs_csp_events")
#Vendor="microsoft" #event.dataset=/entraid/ #repo!="xdr*"
| #event.kind="event" #event.outcome="success"
| array:contains("event.category[]", value="authentication")
| case {
    Vendor.appDisplayName =~ in(values=["Microsoft Azure PowerShell", "Azure Active Directory PowerShell", "Microsoft Graph PowerShell SDK", "Microsoft Graph Command Line Tools", "Microsoft Azure CLI"], ignoreCase=true);
    Vendor.properties.appDisplayName =~ in(values=["Microsoft Azure PowerShell", "Azure Active Directory PowerShell", "Microsoft Graph PowerShell SDK", "Microsoft Graph Command Line Tools", "Microsoft Azure CLI"], ignoreCase=true);
  }
| coalesce([user.email, user.full_name], as=_userPrincipalName)
| coalesce([Vendor.riskState, Vendor.properties.riskState], as=_riskState)
| asn(source.ip)
| table([@timestamp, _userPrincipalName, Vendor.appDisplayName, source.ip, source.ip.org, source.geo.country_name, _riskState, user_agent.original], limit=50, sortby=@timestamp, order=desc)
```
**Time range:** 7d

### 6. Non-Registered Device Sign-Ins (Device Trust Investigation)

Find successful sign-ins from unregistered devices without MFA.

```cql
(#repo="microsoft_graphapi" OR #repo="3pi_microsoft_entra_id" OR #repo="fcs_csp_events")
#Vendor="microsoft" #event.dataset=/entraid/ #repo!="xdr*"
| #event.kind="event" #event.outcome="success"
| Vendor.AuthenticationRequirement=/^singleFactorAuthentication$/i
| Vendor.DeviceDetail.trusttype=/^$/i
| coalesce([Vendor.riskState, Vendor.properties.riskState], as=_riskState)
| _riskState=/^atRisk$/i
| coalesce([user.email, user.full_name], as=_userPrincipalName)
| coalesce([Vendor.appDisplayName, Vendor.properties.appDisplayName], as=_appDisplayName)
| asn(source.ip)
| table([@timestamp, _userPrincipalName, _appDisplayName, source.ip, source.ip.org, source.geo.country_name, Vendor.AuthenticationRequirement, Vendor.DeviceDetail.trusttype, _riskState], limit=50, sortby=@timestamp, order=desc)
```
**Time range:** 24h

### 7. MFA Denial / Fraud Reports

Check for MFA fatigue attacks (user denied MFA they didn't initiate).

```cql
(#repo="microsoft_graphapi" OR #repo="3pi_microsoft_entra_id" OR #repo="fcs_csp_events")
#Vendor="microsoft" #event.dataset=/entraid/ #repo!="xdr*"
| #event.kind="event" #event.outcome="failure"
| Vendor.initiatedBy.app.displayName="Azure MFA StrongAuthenticationService"
| coalesce([user.email, user.full_name], as=_userPrincipalName)
| asn(source.ip)
| table([@timestamp, _userPrincipalName, source.ip, source.ip.org, source.geo.city_name, source.geo.country_name, Vendor.status.failureReason, user_agent.original], limit=50, sortby=@timestamp, order=desc)
```
**Time range:** 24h

### 8. Conditional Access Failures for a User

Check if CA policies are blocking the sign-in (good — security controls working).

```cql
(#repo="microsoft_graphapi" OR #repo="3pi_microsoft_entra_id" OR #repo="fcs_csp_events")
#Vendor="microsoft" #event.dataset=/entraid/ #repo!="xdr*"
| #event.kind="event"
| Vendor.status.errorCode=53003 Vendor.conditionalAccessStatus="failure"
| coalesce([user.email, user.full_name], as=_userPrincipalName)
| _userPrincipalName="{{user}}"
| coalesce([Vendor.appDisplayName, Vendor.properties.appDisplayName], as=_appDisplayName)
| asn(source.ip)
| table([@timestamp, _userPrincipalName, _appDisplayName, source.ip, source.ip.org, source.geo.country_name, Vendor.status.failureReason, user_agent.original], limit=50, sortby=@timestamp, order=desc)
```
**Time range:** 7d

## Triage Checklist

1. **What detection triggered?** Match the alert name to the detection template in `resources/detections/microsoft/` to understand the exact CQL logic that fired.
2. **Is the sign-in successful or failed?** Failed sign-ins blocked by CA/MFA are security controls working. Successful risky sign-ins are more concerning.
3. **What's the risk level and risk event type?** `medium`/`high` from EntraID Identity Protection with specific `riskEventTypes_v2` is more concerning than `none`.
4. **Is the IP domestic (US)?** Non-US = investigate unless user is in International Travel group.
5. **Is the ASN a legitimate ISP or a VPS/proxy?** Residential ISPs are expected. PacketHub, DigitalOcean, Vultr, OVH, etc. are suspicious.
6. **Is the device registered?** Empty `trusttype` = unregistered device. Combined with single-factor auth = high risk.
7. **Is this a CLI tool sign-in?** Azure PowerShell/CLI from non-admin users is suspicious. Check if user is in the 3 Global Admin / 3 IT Support tech group.
8. **Is there an AiTM pattern?** Same correlation ID with both failures and success + medium/high risk = potential AiTM phishing.
9. **MFA denied?** If MFA was denied by the user, they may be under MFA fatigue attack. Check how many MFA prompts they received.

## Finding the Detection Template

```bash
# Search by alert name substring
grep -r "Risky Sign" resources/detections/microsoft/ --include="*.yaml" -l
grep -r "Account Lockout" resources/detections/microsoft/ --include="*.yaml" -l
```

Or use `Grep` tool: search for the alert name in `resources/detections/microsoft/`.

## Common FP Patterns

- **CA failure on legitimate app**: User trying to access an app from a location/device that CA policies block — security working as intended
- **Account lockout from automation**: Service accounts or automated tools retrying with stale credentials
- **Risk level inflation**: EntraID sometimes assigns medium risk to VPN users whose IP changed recently
- **SA account admin activity**: `FLastSA@acmecorp.com` accounts performing legitimate admin tasks
- **Password spray false positive**: Multiple users on shared office network (same IP) having individual password issues

## Classification Guidance

| Detection Type | Likely FP | Likely TP |
|---|---|---|
| Risky sign-in | Residential IP, known device, user confirms activity | VPS IP, unregistered device, user denies activity |
| Account lockout | User forgot password, automation retry | Rapid lockout across multiple accounts from same IP |
| MFA denied | User accidentally denied, fat-finger | Multiple denials user didn't initiate (MFA fatigue) |
| AiTM sequence | Single correlation ID with only one failure code | Multi-error sequence + success + high risk + suspicious IP |
| CLI tool sign-in | Admin user (SA account) doing normal admin work | Non-admin user, or admin at unusual time from unusual IP |
| CA failure | Expected block from policy (non-compliant device) | Repeated attempts to bypass CA from suspicious source |

## Closing the Alert

**FP:** `mcp__crowdstrike__update_alert_status(status="closed", comment="FP — <reason>", tags=["false_positive"])`

**TP:** Escalate via Phase 3C workflow. `mcp__crowdstrike__update_alert_status(status="in_progress", comment="TP confirmed: <summary>", tags=["true_positive"])`

**Tuning needed:** If FP is recurring, proceed to Phase 3B — find the detection template in `resources/detections/microsoft/` and propose a minimal exclusion.
