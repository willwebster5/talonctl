<!-- UPDATE THIS FILE after every triage session.
Record: new FP/TP patterns, tuning decisions, useful hunting queries, investigation techniques.
This is your working memory — update freely. -->

# SOC Skill Memory

## Known False Positive Patterns

### AWS CloudTrail
<!-- Add your AWS CloudTrail FP patterns here. Examples: CI/CD automation, sandbox accounts, known service roles. -->

### Microsoft EntraID
<!-- Add your EntraID FP patterns here. Examples: admin consent flows, dynamic group changes, SA account activity. -->

### Cloud SASE
<!-- Add your Cloud SASE FP patterns here. Examples: VPN reconnect alerts. -->

### Microsoft Intune
<!-- Add your Intune FP patterns here. Examples: device compliance drift. -->

### Network/DNS
<!-- Add your network/DNS FP patterns here. Examples: CDN traffic, OAuth exchanges, DNS-SD queries. -->

### CrowdStrike Endpoint / IMDS
<!-- Add your endpoint/IMDS FP patterns here. Examples: IMDS credential retrieval, legitimate software installs. -->

### PhishER / KnowBe4
<!-- Add your PhishER FP patterns here. Examples: known-good email domains, CDN auto-loads. -->

### Windows Admin Login Detection (NGSIEM)
<!-- Add your Windows admin login FP patterns here. -->

### GitHub
<!-- Add your GitHub FP patterns here. Examples: branch cleanup, direct push detection status. -->

### CrowdStrike EDR
<!-- Add your EDR FP patterns here. Examples: legitimate installs, WinRAR from explorer, USB personal use. -->

## Known True Positive Indicators

<!-- Add confirmed TP patterns here as they are discovered during triage sessions. -->

## Tuning Decisions Log
<!-- Add tuning decisions here in reverse chronological order. Format:
- **YYYY-MM-DD** `detection_name`: Description of change, root cause, and outcome.
-->

## Tuning Backlog → See `TUNING_BACKLOG.md`
Load when doing detection engineering or tuning work.

## Detection Ideas → See `DETECTION_IDEAS.md`
Load when building new detections.

## Useful Hunting Queries

<!-- Add your verified CQL hunting query templates here. Use {{placeholder}} for substitution values. Examples:

### EDR DNS — Domain Hunt (correct syntax)
```cql
#event_simpleName=DnsRequest DomainName=*example.com* | table([@timestamp, UserName, ComputerName, DomainName, ContextBaseFileName], limit=50, sortby=@timestamp, order=asc)
```
-->

## Investigation Techniques
<!-- Add investigation techniques here. Examples: cross-source correlation, temporal analysis, process genealogy, cloud asset verification. -->
