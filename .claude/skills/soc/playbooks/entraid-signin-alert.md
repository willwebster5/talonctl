# Playbook: EntraID Third-Party Sign-In Alert

**Triggers on:** `thirdparty:` composite ID prefix, alert name `sign-in-activity`
**Source:** Microsoft EntraID connector forwarding sign-in risk alerts into CrowdStrike
**Tunable in NGSIEM:** No — tuning must happen in EntraID Conditional Access policies

## What This Alert Means

EntraID Identity Protection flagged a sign-in as risky and forwarded it to CrowdStrike via the third-party connector. The alert payload contains limited fields compared to raw sign-in logs — notably it may lack app name, risk detail, CA policy results, and detailed error codes.

## Key Fields in the Third-Party Alert Payload

From `alert_analysis` response:
```
user_name / user_names[]        — UPN (e.g., jdoe@acmecorp.com)
user_id / user_sid              — EntraID object ID (GUID)
source_endpoint_address_ip4     — source IP
local_address_ip4               — source IP (duplicate)
user_agent                      — browser/device user agent
categorization                  — alert classification string
source_products[]               — ["Microsoft Entraid"]
source_vendors[]                — ["Microsoft"]
timestamp                       — when the sign-in occurred
```

## Investigation Queries

### 1. User's Recent Sign-In History (7d)

Pull all sign-in events for this user to establish baseline and spot anomalies.

```cql
(#repo="microsoft_graphapi" OR #repo="3pi_microsoft_entra_id" OR #repo="fcs_csp_events")
#Vendor="microsoft" #event.dataset=/entraid\.signin/ #repo!="xdr*"
| #event.kind="event"
| coalesce([user.email, user.full_name], as=_userPrincipalName)
| _userPrincipalName="{{user}}"
| coalesce([Vendor.appDisplayName, Vendor.properties.appDisplayName], as=_appDisplayName)
| coalesce([Vendor.riskLevelDuringSignIn, Vendor.properties.riskLevelDuringSignIn], as=_riskLevel)
| coalesce([Vendor.riskState, Vendor.properties.riskState], as=_riskState)
| asn(source.ip)
| table([@timestamp, _userPrincipalName, #event.outcome, error.code, _appDisplayName, source.ip, source.ip.org, source.geo.city_name, source.geo.country_name, _riskLevel, _riskState, user_agent.original], limit=50, sortby=@timestamp, order=desc)
```
**Time range:** 7d

### 2. All Activity from the Source IP (7d)

Determine if this IP is used by other users (shared VPN/office) or only this actor.

```cql
(#repo="microsoft_graphapi" OR #repo="3pi_microsoft_entra_id" OR #repo="fcs_csp_events")
#Vendor="microsoft" #event.dataset=/entraid\.signin/ #repo!="xdr*"
| #event.kind="event"
| source.ip="{{ip}}"
| coalesce([user.email, user.full_name], as=_userPrincipalName)
| coalesce([Vendor.appDisplayName, Vendor.properties.appDisplayName], as=_appDisplayName)
| asn(source.ip)
| table([@timestamp, _userPrincipalName, #event.outcome, error.code, _appDisplayName, source.ip.org, source.geo.city_name, source.geo.country_name, user_agent.original], limit=50, sortby=@timestamp, order=desc)
```
**Time range:** 7d

### 3. Cross-Source Activity for the User (24h)

Check what else this user did across AWS, SASE, Google around the alert time.

```cql
"{{user}}"
| #repo!="xdr*"
| table([@timestamp, #Vendor, #Product, #event.dataset, event.action, source.ip, #event.outcome], limit=50, sortby=@timestamp, order=desc)
```
**Time range:** 24h (centered on alert timestamp)

### 4. IP Reputation Check

Run ASN lookup and check if the IP appears in IOC feeds.

```cql
(#repo="microsoft_graphapi" OR #repo="3pi_microsoft_entra_id" OR #repo="fcs_csp_events")
#Vendor="microsoft" #event.dataset=/entraid\.signin/ #repo!="xdr*"
| source.ip="{{ip}}"
| #event.kind="event"
| asn(source.ip)
| ipLocation(source.ip)
| ioc:lookup(field=[source.ip], type="ip_address", confidenceThreshold="low")
| groupBy([source.ip], function=[
    count(as=total_events),
    count(field=source.ip, distinct=true),
    selectLast([source.ip.org, source.ip.country, source.ip.city, ioc.detected])
  ])
```
**Time range:** 30d

### 5. User's Distinct Source IPs (30d)

Establish the user's normal IP footprint to identify anomalous sources.

```cql
(#repo="microsoft_graphapi" OR #repo="3pi_microsoft_entra_id" OR #repo="fcs_csp_events")
#Vendor="microsoft" #event.dataset=/entraid\.signin/ #repo!="xdr*"
| #event.kind="event" #event.outcome="success"
| coalesce([user.email, user.full_name], as=_userPrincipalName)
| _userPrincipalName="{{user}}"
| asn(source.ip)
| ipLocation(source.ip)
| groupBy([source.ip], function=[
    count(as=sign_in_count),
    min(@timestamp, as=first_seen),
    max(@timestamp, as=last_seen),
    selectLast([source.ip.org, source.ip.country, source.ip.city])
  ])
| sort(sign_in_count, order=desc)
```
**Time range:** 30d

## Triage Checklist

1. **Is the IP domestic (US)?** All employees are US-based. Non-US IPs require scrutiny unless the user is in the International Travel EntraID exclusion group.
2. **Is the IP a known ISP or corporate VPN?** Residential ISPs (Comcast, Verizon, AT&T) and SASE VPN IPs are expected. VPS/hosting/proxy providers (PacketHub, DigitalOcean, AWS, etc.) are suspicious.
3. **Does the user agent match the user's known devices?** Check if iPhone/Android/Mac/Windows matches their device type from environmental context. Mac users = executives and engineers.
4. **Is this a known application?** Office 365, Teams, Outlook are normal. CLI tools (Azure PowerShell, Graph SDK) from non-admins are suspicious.
5. **Does the user have other sign-ins from this IP?** First-time IP for the user is more suspicious than a regularly used one.
6. **What did EntraID risk engine flag?** The `categorization` field in the third-party payload hints at the risk type (e.g., `authentication-threat:indicator-start`).
7. **Cross-source check:** Did SASE VPN show a connection from this user around the same time? If yes, the IP should match SASE's egress.

## Common FP Patterns

- **Mobile sign-in from residential IP**: User on iPhone/Android at home or on cellular — residential ISP is expected
- **New ISP after travel/office change**: User recently changed locations, new IP is from a legitimate US ISP
- **SASE VPN not connected**: User on mobile device without SASE, so IP is their raw ISP instead of SASE egress
- **EntraID risk engine false positive**: Microsoft sometimes flags legitimate sign-ins as risky, especially from new IPs or devices

## Classification Guidance

| Signal | Likely FP | Likely TP |
|--------|-----------|-----------|
| IP geo | US, residential ISP | Non-US, or VPS/proxy/hosting provider |
| User agent | Matches known device type | Unusual or spoofed UA |
| Sign-in history | IP seen before for this user | First-time IP, no prior history |
| Cross-source | SASE connected from same region | No SASE activity, or SASE from different location |
| Risk level | Low or none from raw logs | Medium/high with risk event types present |
| Time | Business hours for user's timezone | Off-hours with no business justification |

## Closing the Alert

**FP:** `mcp__crowdstrike__update_alert_status(status="closed", comment="FP — <reason>. Third-party alert, not tunable in NGSIEM.", tags=["false_positive", "third_party"])`

**TP:** Escalate via Phase 3C workflow. `mcp__crowdstrike__update_alert_status(status="in_progress", comment="TP confirmed: <summary>", tags=["true_positive"])`
