# talonctl-demo — Showcase Repository Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create a showcase repository demonstrating AI-assisted detection-as-code for the fictional "Pinnacle Technology" company, wiring together talonctl, crowdstrike-mcp, and agent-skills.

**Architecture:** New repo with talonctl project structure. Knowledge base populated for Pinnacle's AWS + EntraID + GitHub + Google Workspace stack. Seeded with generic detection rules. README targets security engineers exploring detection-as-code.

**Tech Stack:** talonctl (pip-installed CLI), crowdstrike-mcp (pip-installed MCP server), agent-skills (Claude Code plugins), YAML detection templates, Markdown knowledge base

**Dependencies:** talonctl pip packaging, crowdstrike-mcp pip packaging, and agent-skills polish should be completed first.

---

### File Map

**Create (all new files in new repo):**
- `README.md` — Project overview and getting started guide
- `CLAUDE.md` — Integrated project instructions for Claude Code
- `LICENSE` — MIT
- `.gitignore` — Standard Python + talonctl patterns
- `.mcp.json` — CrowdStrike MCP server configuration
- `.claude/settings.json` — Agent-skills plugin references
- `knowledge/INDEX.md` — Knowledge base routing table
- `knowledge/context/environmental-context.md` — Pinnacle's infrastructure profile
- `knowledge/patterns/aws.md` — AWS FP/TP patterns
- `knowledge/patterns/entraid.md` — EntraID patterns
- `knowledge/patterns/github.md` — GitHub audit log patterns
- `knowledge/patterns/google.md` — Google Workspace patterns
- `knowledge/techniques/investigation-techniques.md` — Generic investigation queries
- `knowledge/tuning/tuning-backlog.md` — Tuning queue
- `knowledge/tuning/tuning-log.md` — Historical tuning decisions
- `knowledge/metrics/detection-metrics.jsonl` — Empty metrics file
- `knowledge/hunts/.gitkeep` — Empty hunts directory
- `knowledge/ideas/detection-ideas.md` — Seed detection concepts
- `resources/detections/generic_network_tor_traffic.yaml` — TOR traffic detection
- `.crowdstrike/deployed_state.json` — Empty initial state

---

### Task 1: Create repository and basic structure

- [ ] **Step 1: Create the repo on GitHub**

```bash
gh repo create willwebster5/talonctl-demo --public --description "AI-assisted detection-as-code demo — talonctl + crowdstrike-mcp + agent-skills" --license MIT
```

- [ ] **Step 2: Clone and set up**

```bash
cd /home/will/projects
git clone git@github.com:willwebster5/talonctl-demo.git
cd talonctl-demo
```

- [ ] **Step 3: Create directory structure**

```bash
mkdir -p .claude
mkdir -p .crowdstrike
mkdir -p knowledge/context
mkdir -p knowledge/patterns
mkdir -p knowledge/techniques
mkdir -p knowledge/tuning
mkdir -p knowledge/metrics
mkdir -p knowledge/hunts
mkdir -p knowledge/ideas
mkdir -p resources/detections
mkdir -p resources/saved_searches
mkdir -p resources/dashboards
```

- [ ] **Step 4: Create .gitignore**

```gitignore
# Python
__pycache__/
*.py[cod]
.venv/
*.egg-info/

# talonctl state backups
.crowdstrike/backups/

# Credentials
credentials.json

# OS
.DS_Store
Thumbs.db

# IDE
.vscode/
.idea/

# Working documents
docs/superpowers/
```

- [ ] **Step 5: Create empty state file**

`.crowdstrike/deployed_state.json`:
```json
{
  "format_version": "3.0",
  "resources": {}
}
```

- [ ] **Step 6: Create placeholder files**

```bash
touch knowledge/metrics/detection-metrics.jsonl
touch knowledge/hunts/.gitkeep
```

- [ ] **Step 7: Commit**

```bash
git add .
git commit -m "feat: initial project structure"
```

---

### Task 2: Create tool configuration files

**Files:**
- Create: `.mcp.json`
- Create: `.claude/settings.json`

- [ ] **Step 1: Create `.mcp.json`**

```json
{
  "mcpServers": {
    "crowdstrike": {
      "command": "crowdstrike-mcp",
      "args": ["--allow-writes"]
    }
  }
}
```

- [ ] **Step 2: Create `.claude/settings.json`**

```json
{
  "permissions": {
    "allow": [
      "mcp__crowdstrike__*"
    ]
  }
}
```

Note: Agent-skills plugins are installed at the user level via the Claude Code plugin marketplace, not per-project. The `.claude/settings.json` just pre-approves MCP tool permissions.

- [ ] **Step 3: Commit**

```bash
git add .mcp.json .claude/settings.json
git commit -m "feat: add MCP and Claude Code configuration"
```

---

### Task 3: Create environmental context for Pinnacle Technology

**Files:**
- Create: `knowledge/context/environmental-context.md`

- [ ] **Step 1: Write environmental-context.md**

```markdown
<!-- TIER: L1 | LOADED BY: every session | PURPOSE: Ground all analysis in Pinnacle's environment -->
<!-- UPDATE: When infrastructure changes (new services, team changes, data source additions) -->

# Pinnacle Technology — Environmental Context

## Company Profile

- **Industry:** B2B SaaS (developer productivity tools)
- **Headcount:** ~200 total, ~50 engineers with production access
- **Security team:** 5 (1 manager, 2 detection engineers, 2 SOC analysts)
- **Compliance:** SOC 2 Type II

## Cloud Infrastructure

### AWS (Primary Cloud)
- **Accounts:** `pinnacle-prod` (112233445566), `pinnacle-staging` (223344556677), `pinnacle-dev` (334455667788)
- **Primary region:** us-east-1 (some workloads in us-west-2)
- **Key services:** EC2, ECS (containerized apps), S3, RDS (PostgreSQL), Lambda, CloudFront
- **Logging:** CloudTrail (all accounts, all regions), VPC Flow Logs (prod only), S3 access logs
- **CI/CD service accounts:** `github-actions-deploy`, `terraform-automation`
- **Known noise:** `terraform-automation` makes frequent IAM and Security Group changes during business hours

### Identity — EntraID
- **Tenant:** pinnacletech.onmicrosoft.com
- **SSO apps:** AWS SSO, GitHub, Google Workspace, Slack, Jira, Datadog
- **Conditional Access:** MFA required for all users, block legacy auth, compliant device required for prod AWS
- **Break-glass accounts:** `emergency-admin@pinnacletech.com` (alerts on any use)
- **Service accounts:** `svc-sso-sync`, `svc-scim-provisioning`
- **Known noise:** `svc-scim-provisioning` generates high-volume directory sync events

### Source Control — GitHub
- **Org:** `pinnacle-tech`
- **Key repos:** `pinnacle-api` (main product), `pinnacle-infra` (Terraform), `pinnacle-data` (data pipelines)
- **Branch protection:** Required reviews on main for all repos
- **Actions:** Self-hosted runners in `pinnacle-prod` AWS account
- **Known noise:** Dependabot creates many PRs in `pinnacle-api` (automated, expected)

### Collaboration — Google Workspace
- **Domain:** pinnacletech.com
- **Key groups:** `engineering@`, `security@`, `oncall@`
- **DLP:** Basic rules for PII in email/Drive
- **Known noise:** Marketing team uses third-party email tools that trigger suspicious login patterns

## CrowdStrike Deployment

- **Falcon sensor:** All endpoints (macOS and Linux), latest sensor version
- **NGSIEM:** Log aggregation from CloudTrail, EntraID, GitHub, Google Workspace, VPC Flow Logs, Falcon telemetry
- **Fusion:** Automated workflows for alert enrichment and notification

## Data Sources in NGSIEM

| Source | Repository | Volume | Key Fields |
|--------|-----------|--------|------------|
| CloudTrail | search-all | ~5M events/day | eventName, userIdentity, sourceIPAddress, requestParameters |
| EntraID Sign-in Logs | search-all | ~50K events/day | userPrincipalName, appDisplayName, status, ipAddress, riskState |
| EntraID Audit Logs | search-all | ~10K events/day | activityDisplayName, targetResources, initiatedBy |
| GitHub Audit Logs | search-all | ~20K events/day | action, actor, org, repo |
| Google Workspace | search-all | ~30K events/day | event_name, actor.email, target |
| VPC Flow Logs | search-all | ~100M events/day | srcaddr, dstaddr, dstport, action, protocol |
| Falcon Endpoint | xdr_* | varies | event_simpleName, aid, UserName, CommandLine |

## Known Legitimate Patterns

These patterns are expected and should not trigger alerts without additional context:

1. **CI/CD IAM changes:** `github-actions-deploy` and `terraform-automation` make IAM/SG changes during US business hours
2. **SCIM sync floods:** `svc-scim-provisioning` generates bursts of directory events on employee onboarding days
3. **Dependabot PRs:** Automated dependency update PRs in `pinnacle-api` — high volume, expected
4. **Marketing logins:** Marketing team members log in from various IPs due to travel and third-party tools
5. **Break-glass testing:** Quarterly test of `emergency-admin` account (documented, announced)

## Escalation Contacts

| Role | Contact | When |
|------|---------|------|
| SOC Lead | Alex Chen | First escalation for TP alerts |
| Detection Engineering | Jordan Park | Detection tuning, new rule requests |
| Security Manager | Sam Rivera | P1 incidents, compliance questions |
| DevOps On-call | oncall@pinnacletech.com | Infrastructure questions, containment approval |
```

- [ ] **Step 2: Commit**

```bash
git add knowledge/context/environmental-context.md
git commit -m "feat: add Pinnacle Technology environmental context"
```

---

### Task 4: Create knowledge base scaffold

**Files:**
- Create: `knowledge/INDEX.md`
- Create: `knowledge/patterns/aws.md`
- Create: `knowledge/patterns/entraid.md`
- Create: `knowledge/patterns/github.md`
- Create: `knowledge/patterns/google.md`
- Create: `knowledge/techniques/investigation-techniques.md`
- Create: `knowledge/tuning/tuning-backlog.md`
- Create: `knowledge/tuning/tuning-log.md`
- Create: `knowledge/ideas/detection-ideas.md`

- [ ] **Step 1: Create INDEX.md**

```markdown
<!-- TIER: L1 | LOADED BY: every session | PURPOSE: Route to the right knowledge file -->
<!-- UPDATE: After every triage session, hunt, or detection change -->
<!-- KEEP UNDER 150 LINES — this is loaded into context every session -->

# Detection Index

| resource_id | Name | Status | Last Reviewed | Platform |
|-------------|------|--------|---------------|----------|
| generic___network___tor_traffic_to_the_internet | TOR Traffic to the Internet | active | 2026-04-14 | network |

## Quick Stats

- **Total detections:** 1
- **Last triage session:** —
- **Tuning backlog items:** 0
- **Open detection ideas:** 3

## File Map

| Need | File | Tier |
|------|------|------|
| Platform FP/TP patterns | `knowledge/patterns/<platform>.md` | L2 |
| Investigation techniques | `knowledge/techniques/investigation-techniques.md` | L2 |
| Tuning queue | `knowledge/tuning/tuning-backlog.md` | L2 |
| Tuning history | `knowledge/tuning/tuning-log.md` | L3 |
| Per-alert metrics | `knowledge/metrics/detection-metrics.jsonl` | L3 |
| Hunt reports | `knowledge/hunts/<date>-<slug>.md` | L3 |
| Detection ideas | `knowledge/ideas/detection-ideas.md` | L3 |
| Environment context | `knowledge/context/environmental-context.md` | L1 |
```

- [ ] **Step 2: Create pattern files**

Each pattern file starts with headers and format documentation but minimal content — they grow through triage.

`knowledge/patterns/aws.md`:
```markdown
<!-- TIER: L2 | LOADED BY: Phase 3 (Classification) for AWS alerts -->
<!-- UPDATE: After every AWS alert triage — add FP/TP patterns -->

# AWS — FP/TP Patterns

## False Positive Patterns

<!-- Format:
### [Short description]
- **Detection:** resource_id
- **Pattern:** What makes this a FP
- **Identifying fields:** Key fields to check
- **Action:** How to tune (exclusion, threshold, etc.)
-->

### CI/CD IAM Changes
- **Detection:** (applies to future IAM detections)
- **Pattern:** `github-actions-deploy` and `terraform-automation` make IAM/SG changes during business hours
- **Identifying fields:** `userIdentity.arn` contains service account name
- **Action:** Exclude CI/CD service accounts by ARN

## True Positive Indicators

<!-- Format:
### [Short description]
- **Detection:** resource_id
- **Pattern:** What makes this a TP
- **Key evidence:** Fields/values that confirm
-->

(No TP patterns recorded yet)
```

`knowledge/patterns/entraid.md`:
```markdown
<!-- TIER: L2 | LOADED BY: Phase 3 (Classification) for EntraID alerts -->
<!-- UPDATE: After every EntraID alert triage — add FP/TP patterns -->

# EntraID — FP/TP Patterns

## False Positive Patterns

### SCIM Provisioning Sync
- **Detection:** (applies to future EntraID detections)
- **Pattern:** `svc-scim-provisioning` generates directory sync bursts on onboarding days
- **Identifying fields:** `initiatedBy.app.displayName` = "SCIM Connector"
- **Action:** Exclude SCIM service principal from directory change detections

### Marketing Team Travel Logins
- **Detection:** (applies to future sign-in anomaly detections)
- **Pattern:** Marketing team logs in from various IPs due to travel and third-party email tools
- **Identifying fields:** `userPrincipalName` in marketing team, `appDisplayName` = third-party tool
- **Action:** Use group-based risk scoring rather than hard IP blocks

## True Positive Indicators

(No TP patterns recorded yet)
```

`knowledge/patterns/github.md`:
```markdown
<!-- TIER: L2 | LOADED BY: Phase 3 (Classification) for GitHub alerts -->
<!-- UPDATE: After every GitHub alert triage — add FP/TP patterns -->

# GitHub — FP/TP Patterns

## False Positive Patterns

### Dependabot Automated PRs
- **Detection:** (applies to future repo change detections)
- **Pattern:** High volume of PRs from `dependabot[bot]` in `pinnacle-api`
- **Identifying fields:** `actor` = "dependabot[bot]", `action` = "pull_request.created"
- **Action:** Exclude bot actors from PR volume anomaly detections

## True Positive Indicators

(No TP patterns recorded yet)
```

`knowledge/patterns/google.md`:
```markdown
<!-- TIER: L2 | LOADED BY: Phase 3 (Classification) for Google Workspace alerts -->
<!-- UPDATE: After every Google Workspace alert triage — add FP/TP patterns -->

# Google Workspace — FP/TP Patterns

## False Positive Patterns

(No FP patterns recorded yet)

## True Positive Indicators

(No TP patterns recorded yet)
```

- [ ] **Step 3: Create investigation-techniques.md**

```markdown
<!-- TIER: L2 | LOADED BY: Phase 2 (Triage) when investigating alerts -->
<!-- UPDATE: When you discover useful CQL patterns or field gotchas -->

# Investigation Techniques

## Quick Lookups

### User Activity Timeline
```
#repo!=xdr_*
| userIdentity.arn = "<ARN>" OR userPrincipalName = "<UPN>" OR actor = "<username>"
| select([@timestamp, #Vendor, eventName, sourceIPAddress, userAgent])
| sort(@timestamp, order=asc)
```

### IP Reputation Check
```
#repo!=xdr_*
| source.ip = "<IP>" OR destination.ip = "<IP>"
| groupBy([source.ip, destination.ip, #Vendor], function=[count(), min(@timestamp), max(@timestamp)])
```

### Source IP Activity Spread
```
#repo!=xdr_*
| source.ip = "<IP>"
| groupBy([#Vendor, eventName], function=count())
| sort(_count, order=desc)
```

## Field Gotchas

- **CloudTrail userIdentity:** Can be `type=AssumedRole` (role session) or `type=IAMUser` — check `arn` for the actual identity
- **EntraID dual schema:** Sign-in logs use `userPrincipalName`, audit logs use `initiatedBy.user.userPrincipalName` — different fields for the same concept
- **GitHub actor:** Bot accounts end with `[bot]` (e.g., `dependabot[bot]`), service accounts don't
- **VPC Flow Logs:** `action=ACCEPT` means the security group/NACL allowed the traffic, not that a connection was established
```

- [ ] **Step 4: Create tuning files**

`knowledge/tuning/tuning-backlog.md`:
```markdown
<!-- TIER: L2 | LOADED BY: /soc tune and detection engineering sessions -->
<!-- UPDATE: After triage when a detection needs adjustment -->

# Tuning Backlog

<!-- Format:
## [resource_id]
- **Priority:** high/medium/low
- **Issue:** What's wrong
- **Proposed fix:** What to change
- **Alerts:** [composite IDs that triggered this]
- **Added:** YYYY-MM-DD
-->

(No items in backlog)
```

`knowledge/tuning/tuning-log.md`:
```markdown
<!-- TIER: L3 | LOADED BY: on-demand during tuning sessions -->
<!-- UPDATE: After every tuning change is applied -->

# Tuning Log

<!-- Format:
## YYYY-MM-DD — resource_id

**Trigger:** What prompted the tuning
**Change:** Summary of what was modified
**Before:** `<before CQL snippet>`
**After:** `<after CQL snippet>`
**Alerts:** [composite_ids that triggered this]
**Validation:** validate-query result
**PR:** #number
-->

(No tuning changes recorded yet)
```

- [ ] **Step 5: Create detection-ideas.md**

```markdown
<!-- TIER: L3 | LOADED BY: on-demand during detection engineering sessions -->
<!-- UPDATE: When triage or hunting reveals detection gaps -->

# Detection Ideas

## AWS — Unusual Cross-Account AssumeRole
- **Hypothesis:** An attacker with credentials in one account assumes roles in other accounts
- **Data source:** CloudTrail
- **Key fields:** `eventName=AssumeRole`, `resources.ARN` (target), `userIdentity.arn` (source)
- **Challenge:** Need to baseline normal cross-account patterns for CI/CD
- **MITRE:** TA0008:T1550.001 (Lateral Movement / Use Alternate Authentication Material)

## EntraID — Conditional Access Policy Modification
- **Hypothesis:** An attacker with Global Admin disables MFA or device compliance requirements
- **Data source:** EntraID Audit Logs
- **Key fields:** `activityDisplayName=Update conditional access policy`, `targetResources`
- **Challenge:** Legitimate policy updates happen during security team changes
- **MITRE:** TA0005:T1562.001 (Defense Evasion / Impair Defenses: Disable or Modify Tools)

## GitHub — Repository Visibility Change to Public
- **Hypothesis:** Sensitive internal repo accidentally or maliciously made public
- **Data source:** GitHub Audit Logs
- **Key fields:** `action=repo.access`, `visibility=public`
- **Challenge:** Some repos are intentionally public (open source projects)
- **MITRE:** TA0010:T1567 (Exfiltration / Exfiltration Over Web Service)
```

- [ ] **Step 6: Commit**

```bash
git add knowledge/
git commit -m "feat: add knowledge base scaffold for Pinnacle Technology"
```

---

### Task 5: Add seed detection — TOR traffic

**Files:**
- Create: `resources/detections/generic_network_tor_traffic.yaml`

- [ ] **Step 1: Create TOR traffic detection**

Copy and adapt from talonctl's `examples/resources/detection.yaml`. This is a real, deployable, generic detection:

```yaml
resource_id: generic___network___tor_traffic_to_the_internet
name: Generic - Network - TOR Traffic to the Internet
description: |
  Detects traffic associated with TOR applications or ports commonly used by TOR,
  which adversaries might exploit to avoid detection on the environment.
severity: 50
status: active
mitre_attack: ["TA0011:T1090.003"]
ads:
  goal: >
    Detect traffic associated with TOR anonymization network from internal
    networks, which may indicate an adversary attempting to evade network
    monitoring or exfiltrate data through encrypted channels.
  mitre_attack:
    - "Command and Control / Proxy: Multi-hop Proxy (T1090.003)"
  strategy_abstract: >
    Monitors network flow logs for TCP connections to known TOR ports
    (9001, 9030, 9040, 9050, 9051, 9150) from internal RFC1918 addresses,
    plus port 443 with TOR application identification.
  technical_context: >
    Requires network flow logs from supported vendors (Akamai, AWS, Cisco,
    Cloudflare, Corelight, etc.) with destination port and application fields.
    Uses CIDR matching to identify internal-to-external traffic only.
  blind_spots:
    - "TOR over non-standard ports not covered"
    - "TOR bridges using obfs4 transport may not be identified"
    - "Vendors not in the filter list are excluded"
  false_positives:
    - pattern: "Security tool TOR exit node scanning"
      characteristics: "Automated security scanner source IPs"
      tuning: "Add scanner IPs to exclusion list"
      status: "open"
  validation:
    - "Generate TOR traffic from an internal IP to port 9050"
    - "Verify alert fires with correct source/destination fields"
  priority_rationale: >
    Medium severity (50) — TOR usage is suspicious but may have legitimate
    privacy use cases. Requires analyst investigation to determine intent.
  response: "Investigate user, check for data exfiltration, review browsing history"
  ads_created: "2026-04-14"
  ads_author: "talonctl-demo"
search:
  filter: |
    #repo!=xdr_*
    | #Vendor =~ in(values=["akamai","aws","cisco","cloudflare","corelight",
        "extrahop","fortinet","microsoft","netskope","nozomi","paloalto",
        "skyhigh","zscaler"])
    | #event.kind="event"
    | array:contains(array="event.category[]", value="network")
    | network.transport="tcp"
    | case {
        destination.port =~ in(values=["9001", "9030", "9040", "9050", "9051", "9150"]);
        destination.port="443" network.application=/^tor/i
    }
    | cidr(source.ip, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "fe80::/10", "169.254.0.0/16"])
    | !cidr(destination.ip, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "fe80::/10", "169.254.0.0/16"])
  lookback: 1h0m
  trigger_mode: summary
  outcome: detection
  use_ingest_time: true
operation:
  schedule:
    definition: '@every 1h0m'
```

- [ ] **Step 2: Commit**

```bash
git add resources/detections/generic_network_tor_traffic.yaml
git commit -m "feat: add TOR traffic detection (generic, non-proprietary)"
```

---

### Task 6: Create CLAUDE.md

**Files:**
- Create: `CLAUDE.md`

- [ ] **Step 1: Write CLAUDE.md**

This is the integrated version, adapted from talonctl's `CLAUDE.integrated.md` but written for a talonctl *project* (not the talonctl tool itself):

```markdown
# talonctl-demo — Project Instructions

Detection-as-code for Pinnacle Technology's CrowdStrike NGSIEM, powered by talonctl with AI-assisted SOC workflows.

## Overview

This is a [talonctl](https://github.com/willwebster5/talonctl) project — infrastructure as code for CrowdStrike NGSIEM resources. It manages detection rules, saved searches, and dashboards for Pinnacle Technology's security program.

**Tools:**
- **talonctl** — IaC CLI (`talonctl plan`, `talonctl apply`, `talonctl validate`)
- **crowdstrike-mcp** — MCP server bridging Claude to the CrowdStrike Falcon API
- **agent-skills** — Claude Code plugins for SOC workflows, detection engineering, and threat hunting

## Commands

```bash
talonctl validate                    # Validate all templates (no API calls)
talonctl plan                        # Preview what would change
talonctl apply                       # Deploy changes
talonctl import --plan               # Preview importing existing resources
talonctl sync                        # Reconcile state with live tenant
talonctl drift                       # Detect manual console changes
talonctl show                        # Show current state
```

## AI Workflows

| Command | Description |
|---------|-------------|
| `/soc` | SOC operations — triage, daily review, hunt, tune |
| `/research` | Deep technical research with web search |
| `/discuss` | Exploratory discussion mode (read-only) |
| `/hunt` | Autonomous threat hunting |

### SOC Subcommands

```
/soc triage <alert-url-or-id>   — Triage a specific alert
/soc daily [product]             — Review today's untriaged alerts
/soc tune <detection-name>       — Tune a detection for FPs
/soc hunt <IOCs-or-hypothesis>   — Threat hunting mode
```

## Critical Rules

1. **Always plan before apply.** Never blind-deploy.
2. **Never change `resource_id` after deploy.** It destroys and recreates the resource.
3. **Saved search description limit: 2000 characters.** The API silently truncates.
4. **Validate CQL syntax** before committing: `talonctl validate`
5. **Detection tuning requires approval.** The SOC skill presents a diff and waits for confirmation.
6. **Knowledge base files are living documents.** Update `knowledge/` after every triage session.

## Knowledge Base

The `knowledge/` directory holds operational context that compounds over time.

### Tiered Loading

| Tier | Load When | Files |
|------|-----------|-------|
| L1 | Every session | `INDEX.md`, `context/environmental-context.md` |
| L2 | Per-task | `patterns/<platform>.md`, `techniques/investigation-techniques.md`, `tuning/tuning-backlog.md` |
| L3 | On-demand | `tuning/tuning-log.md`, `metrics/detection-metrics.jsonl`, `hunts/*.md`, `ideas/detection-ideas.md` |

### ADS Metadata

Detection templates support an optional `ads:` block for Alerting and Detection Strategy documentation:

```yaml
ads:
  goal: ""              # Required — what behavior does this detect?
  mitre_attack: []      # Analyst-facing MITRE mappings
  strategy_abstract: "" # How the detection works
  technical_context: "" # Data sources, key fields
  blind_spots: []       # Known limitations
  false_positives: []   # FP summaries
  validation: []        # Steps to trigger a TP
  priority_rationale: ""# Why this severity?
  response: ""          # Response steps
```

## Credentials

- **Location:** `~/.config/falcon/credentials.json`
- **Setup:** See talonctl documentation
- **Never commit credentials.**

## Resource Types

| Type | Template Dir | Description |
|------|-------------|-------------|
| Detection | `resources/detections/` | Correlation rules (CQL queries) |
| Saved Search | `resources/saved_searches/` | Reusable CQL functions |
| Dashboard | `resources/dashboards/` | LogScale dashboards |
```

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: add integrated CLAUDE.md for AI-assisted workflows"
```

---

### Task 7: Create README

**Files:**
- Create: `README.md`

- [ ] **Step 1: Write README.md**

```markdown
# talonctl-demo

A working example of AI-assisted detection-as-code for CrowdStrike NGSIEM.

This repo demonstrates the full detection engineering lifecycle — from writing detection rules as YAML templates to deploying them via CI/CD — augmented with AI-powered SOC workflows for triage, tuning, and threat hunting.

## The Tools

| Tool | What it does | Repo |
|------|-------------|------|
| [talonctl](https://github.com/willwebster5/talonctl) | Terraform-like IaC CLI for CrowdStrike NGSIEM | `pip install talonctl` |
| [crowdstrike-mcp](https://github.com/willwebster5/crowdstrike-mcp) | MCP server bridging AI assistants to the Falcon API | `pip install crowdstrike-mcp` |
| [agent-skills](https://github.com/willwebster5/agent-skills) | Claude Code plugins for SOC and detection engineering | Plugin marketplace |

## The Environment

This demo uses a fictional company, **Pinnacle Technology**, a cloud-native SaaS startup with:
- AWS (CloudTrail, VPC Flow Logs)
- EntraID (SSO, Conditional Access)
- GitHub (organization audit logs)
- Google Workspace
- CrowdStrike Falcon (endpoint + NGSIEM)

The `knowledge/` directory contains Pinnacle's environmental context, known FP/TP patterns, and investigation techniques — all fictional but realistic.

## Prerequisites

- CrowdStrike Falcon tenant with NGSIEM
- Python 3.11+
- [Claude Code](https://claude.ai/download)
- API credentials with required scopes (see [talonctl docs](https://github.com/willwebster5/talonctl#api-scopes))

## Quick Start

1. **Install the tools:**
   ```bash
   pip install talonctl crowdstrike-mcp
   ```

2. **Install Claude Code plugins:**
   ```
   /install-plugin willwebster5/agent-skills
   ```

3. **Clone this demo:**
   ```bash
   git clone https://github.com/willwebster5/talonctl-demo.git
   cd talonctl-demo
   ```

4. **Configure credentials:**
   ```bash
   # Create ~/.config/falcon/credentials.json
   mkdir -p ~/.config/falcon
   cat > ~/.config/falcon/credentials.json << 'EOF'
   {
     "falcon_client_id": "YOUR_CLIENT_ID",
     "falcon_client_secret": "YOUR_CLIENT_SECRET",
     "base_url": "US1"
   }
   EOF
   ```

5. **Validate and plan:**
   ```bash
   talonctl validate    # Check templates are valid
   talonctl plan        # See what would deploy
   ```

## Detection-as-Code Lifecycle

```
Write YAML template → talonctl validate → talonctl plan → Review diff → talonctl apply
                                                              ↑
                                                    AI triage/hunting feeds back
                                                    detection ideas and tuning
```

## AI Workflows

With Claude Code and the agent-skills plugins installed, you get:

- **`/soc triage <alert>`** — AI-assisted alert triage with evidence collection
- **`/soc daily`** — Review today's untriaged alerts
- **`/soc tune <detection>`** — Tune a detection for false positives
- **`/hunt hypothesis "<statement>"`** — Autonomous PEAK-framework threat hunting

Each workflow reads from and writes to the `knowledge/` directory, building institutional memory over time.

## Adding Detections

Detection rules in `resources/detections/` must be:
- **Generic** — not tied to a specific customer environment
- **Non-proprietary** — no customer names, internal IPs, or proprietary tool names
- **Complete** — valid CQL, full ADS metadata, MITRE ATT&CK mapping

See the [TOR traffic detection](resources/detections/generic_network_tor_traffic.yaml) for a complete example.

## License

MIT
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: add README with getting started guide"
```

---

### Task 8: Final verification and push

- [ ] **Step 1: Verify repo structure**

```bash
find . -not -path './.git/*' -type f | sort
```

Expected files:
```
./.claude/settings.json
./.crowdstrike/deployed_state.json
./.gitignore
./.mcp.json
./CLAUDE.md
./LICENSE
./README.md
./knowledge/INDEX.md
./knowledge/context/environmental-context.md
./knowledge/hunts/.gitkeep
./knowledge/ideas/detection-ideas.md
./knowledge/metrics/detection-metrics.jsonl
./knowledge/patterns/aws.md
./knowledge/patterns/entraid.md
./knowledge/patterns/github.md
./knowledge/patterns/google.md
./knowledge/techniques/investigation-techniques.md
./knowledge/tuning/tuning-backlog.md
./knowledge/tuning/tuning-log.md
./resources/detections/generic_network_tor_traffic.yaml
```

- [ ] **Step 2: Verify YAML is valid**

```bash
python3 -c "import yaml; yaml.safe_load(open('resources/detections/generic_network_tor_traffic.yaml'))" && echo "OK"
```

Expected: `OK`

- [ ] **Step 3: Push to remote**

```bash
git push origin main
```
