# Playbook: KnowBe4 PhishER — Threat Link DNS Alert

> **WIP** — based on a single triage session (2026-03-16). Field schemas and FP patterns are grounded but investigation workflows may be incomplete. Update as more alerts are triaged.

**Triggers on:**
- `ngsiem:` prefix + detection name `KnowBe4 - PhishER - Threat Link Domain Queried by Endpoint`

**Source:**
- KnowBe4 PhishER (reported emails) correlated against CrowdStrike EDR DnsRequest telemetry
- Detection template: `resources/detections/knowbe4/knowbe4___phisher___threat_link_dns_hit.yaml`

**Tunable in NGSIEM:** Yes — template in `resources/detections/knowbe4/`

---

## How This Detection Works

PhishER receives reported phishing emails from users. The detection:
1. Extracts **all links** from the email body (`split("Vendor.links")` — not just the first link)
2. Strips each link down to its domain (`phisher._link_domain`)
3. Applies an exclusion list of known-good CDN/provider domains
4. Correlates remaining domains against `#event_simpleName=DnsRequest` telemetry within a **4-hour window** of the report

A match means **some endpoint on the network resolved a domain that appeared in a reported phishing email**. It does NOT necessarily mean the user clicked the phishing link — see FP patterns below.

---

## Alert Event Field Schema

From the `alert_analysis` match events (`ngsiem-rule-match-event`):

| Field | Description |
|-------|-------------|
| `phisher.Email.reported_by` | Email address of the user who reported the email to PhishER |
| `phisher.Email.sender_domain` | Domain of the email sender (often a compromised legitimate domain) |
| `phisher._link_domain` | Extracted domain from the email body that matched a DNS query |
| `dns.ComputerName` | Hostname of the endpoint that made the DNS query |
| `dns.UserName` | User logged into the endpoint at query time |

**Key correlation signal:** If `dns.ComputerName` matches the reporter's device → higher confidence the reporter clicked before reporting. If it's a different device → someone else on the network may have received and clicked the same email.

---

## Known False Positive Patterns

### 1. Akamai Image CDN (`*.akamaihd.net`)
HTML phishing emails frequently embed image URLs (logos, banners, tracking pixels) hosted on Akamai's CDN (`akamaihd.net`). Email clients auto-load these images on receipt — triggering a DnsRequest event from the mail client or browser — before the user clicks anything.

**How to identify:** Check `ContextBaseFileName` in the raw DNS event. Image auto-load comes from mail clients or browsers, not a dedicated click-through handler. Also: if multiple machines resolve the same `*.akamaihd.net` domain within a short window, it's image auto-load, not coordinated clicks.

**Current exclusions:** `docucdn-a.akamaihd.net` was the specific domain observed 2026-03-16. The broader `*.akamaihd.net` pattern should be added to the exclusion list.

### 2. Microsoft Dynamics 365 Marketing (`public-usa.mkt.dynamics.com`)
Legitimate businesses use Dynamics 365 as their email marketing platform. Links to this domain appear in marketing/promotional emails that users report as suspected phishing (often correctly — the *sender* is suspicious, but the links are platform infrastructure).

**Exclude:** `public-usa.mkt.dynamics.com` and potentially the broader `*.mkt.dynamics.com` pattern.

### 3. Trusted URL Shorteners / Redirect Services Used as Cloakers
Attackers use legitimate redirect services (Monday.com, Bit.ly, etc.) to wrap phishing URLs. The PhishER detection extracts the *wrapper domain* (e.g., `trackingservice.monday.com`), which is on the exclusion list — so the detection **does not fire** on the actual phishing link. This is a detection gap, not a FP. See Detection Gaps section.

---

## Triage Workflow

### Step 1 — Identify the trigger domain
From the alert match events, extract:
- `phisher._link_domain` — what domain triggered the detection
- `phisher.Email.sender_domain` — what domain sent the email
- `phisher.Email.reported_by` — who reported it
- `dns.ComputerName` — which device resolved the domain

### Step 2 — Classify the trigger domain
Ask: is this domain a **link in the email** (something a user would click) or **infrastructure in the email** (image src, tracking pixel, CDN asset)?

| Domain type | Examples | Likely FP? |
|-------------|---------|------------|
| Akamai CDN | `*.akamaihd.net` | Yes — image auto-load |
| Microsoft platform | `*.mkt.dynamics.com`, `aka.ms` | Yes — platform infra |
| Email provider | `gmail.com`, `outlook.com`, `yahoo.com` | Yes — mentioned in body |
| Unknown domain | Random string, foreign TLD, lookalike | Investigate |
| Compromised-looking legitimate | `mveyecare.com`, small business site | Investigate |

### Step 3 — Verify with DNS telemetry
If the trigger domain warrants investigation, pull the raw DNS events with the **correct field syntax**:

```cql
#event_simpleName=DnsRequest DomainName=*<trigger_domain>*
| table([@timestamp, UserName, ComputerName, DomainName, ContextBaseFileName], limit=50, sortby=@timestamp, order=asc)
```

Check `ContextBaseFileName`:
- `chrome.exe`, `Safari`, `msedge.exe` — likely browser/webmail image load
- `OUTLOOK.EXE`, `olk.exe` — desktop email client render
- Multiple machines in short window → almost certainly image auto-load

### Step 4 — Find the real phishing link
The PhishER detection may fire on a CDN/infrastructure domain while the actual phishing link is present elsewhere in the email. Look at ALL link domains extracted from the email, not just the one that triggered.

**Monday.com / redirect cloaker pattern:**
If you see a `trackingservice.monday.com/tracker/link?token=<JWT>` URL in the email, decode the JWT payload — the `originalUrl` field contains the real destination:

```python
import base64, json
payload = "<middle_segment_of_jwt>"
# pad to multiple of 4
padded = payload + '=' * (4 - len(payload) % 4)
print(json.loads(base64.b64decode(padded)))
# → {"originalUrl": "https://actual-phishing-site.com/path", ...}
```

### Step 5 — Hunt for click-through to real destination

**DNS vs. HTTP disambiguation:** DNS resolution fires *before* the HTTP connection is established. A DNS hit means the browser looked up the domain — it does NOT mean the payload was delivered. Always check SASE for what happened to the subsequent HTTP request.

```cql
// DNS — who resolved the phishing domain?
#event_simpleName=DnsRequest DomainName=*<phishing_domain>*
| table([@timestamp, UserName, ComputerName, DomainName, ContextBaseFileName], limit=20)
```

```cql
// SASE — was the HTTP connection allowed or blocked?
#Vendor="sase" (Vendor.dest_domain=*<phishing_domain>* OR Vendor.url=*<phishing_domain>*)
| table([
    @timestamp,
    Vendor.vpn_user_email,
    Vendor.device_name,
    Vendor.dest_domain,
    Vendor.url,
    Vendor.action,
    Vendor.rule_name,
    Vendor.categories,
    Vendor.event_type
  ], limit=20, sortby=@timestamp)
```

**Interpreting SASE results:**

| `Vendor.action` | `Vendor.event_type` | Meaning |
|-----------------|---------------------|---------|
| `Block` | `Internet Firewall` | SASE blocked by category/reputation rule — **payload not delivered** |
| `Block` | `IPS` | SASE IPS signature match — **payload not delivered** |
| `Allow` | `Internet Firewall` | Traffic passed through — **investigate endpoint** |
| No SASE events | — | SASE may not have visibility (split tunnel gap, direct connection) — **investigate endpoint** |

**SASE block = no follow-up on payload**, but still:
- Identify the user via `Vendor.vpn_user_email` and `Vendor.device_name`
- Confirm the email was quarantined in PhishER
- Note that user followed the correct process (report → click → block page)

**No SASE events + DNS hit = higher priority** — possible successful delivery. Run endpoint activity query (Step 6).

### Step 6 — Assess campaign scope
If DNS hits exist on the real phishing destination:

```cql
// Who else got the email? (same sender domain, past 7d)
// Check PhishER directly — or look at other PhishER alerts for same sender_domain

// Endpoint activity post-DNS on affected hosts
#event_simpleName=ProcessRollup2 ComputerName="<affected_host>"
| table([@timestamp, UserName, FileName, CommandLine, ParentBaseFileName], limit=50, sortby=@timestamp, order=asc)
```

---

## Tuning Guidance

Detection template: `resources/detections/knowbe4/knowbe4___phisher___threat_link_dns_hit.yaml`

**Exclusion list approach:** The detection uses a regex exclusion on `phisher._link_domain`. Add new FP domains to this regex. Current exclusions (as of 2026-03-13): email providers (gmail, outlook, yahoo, hotmail, protonmail, icloud, aol), URL shorteners (aka.ms, bit.ly), org domain (acmecorp.com), known vendors (chainguard.dev).

**Still needed (as of 2026-03-16):**
- `*.akamaihd.net` — Akamai image CDN
- `public-usa.mkt.dynamics.com` — Microsoft Dynamics Marketing (consider `*.mkt.dynamics.com`)

---

## Detection Gaps

### Redirect cloakers (Monday.com, Bit.ly wrapped phishing)
Attackers wrap phishing URLs in trusted redirect services. The detection sees only the wrapper domain (excluded as trusted) and never fires on the actual destination. No current coverage.

**Potential improvement:** Detect based on JWT token patterns in URLs, or flag known redirect services pointing to uncommon destinations — but this likely needs to happen in PhishER itself, not NGSIEM.

### Image auto-load vs. click disambiguation
The detection currently fires on ANY domain from the email that gets resolved — including image CDN domains auto-loaded on email receipt. The `ContextBaseFileName` field can distinguish mail client from browser, but this isn't currently used in the detection filter.

**Potential improvement:** Add `ContextBaseFileName` filter to exclude resolutions from known image-rendering processes when the domain is a CDN pattern.

> **Detection ideas** for behavioral correlations (SASE block confirmation, multi-recipient campaign) are tracked in `.claude/skills/soc/DETECTION_IDEAS.md`.
