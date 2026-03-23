# Getting Started

Detailed onboarding walkthrough for ClaudeStrike.

## 1. Prerequisites

You need:

- **CrowdStrike Falcon tenant** with NG-SIEM (LogScale) enabled
- **CrowdStrike API credentials** — create an API client in the Falcon Console:
  - Go to **Support & Resources > API Clients and Keys**
  - Create a new client with scopes: Alerts (Read/Write), Custom IOA Rules (Read/Write), Hosts (Read), Real Time Response (Read/Write), Saved Searches (Read/Write), Workflows (Read/Write), Cases (Read/Write)
- **Claude Code CLI** — installed and authenticated ([docs](https://docs.anthropic.com/en/docs/claude-code))
- **Python 3.11+** — with pip
- **Git**
- **A CrowdStrike MCP server** — the SOC skill uses MCP tools to query alerts and run CQL. You'll need a running MCP server that exposes tools like `ngsiem_query`, `get_alerts`, `alert_analysis`, etc.

## 2. Installation

```bash
# Clone the repo
git clone https://github.com/yourusername/ClaudeStrike.git
cd ClaudeStrike

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

Dependencies:
- `crowdstrike-falconpy` — CrowdStrike API SDK
- `pyyaml` — YAML template parsing
- `rich` — terminal output formatting
- `requests` — HTTP calls
- `pytest` — testing

## 3. Setup

Run the setup wizard:

```bash
python scripts/setup.py
```

The wizard will:
1. Prompt for your **Client ID** and **Client Secret**
2. Ask you to select your **cloud region** (US1, US2, EU1, GOV1)
3. Validate the connection against the CrowdStrike API
4. Save credentials to `~/.config/falcon/credentials.json` with `600` permissions

If you already have credentials saved, it will show you the existing config and ask if you want to reconfigure.

### Manual Setup

If you prefer to skip the wizard:

```bash
mkdir -p ~/.config/falcon
cat > ~/.config/falcon/credentials.json << 'EOF'
{
  "falcon_client_id": "YOUR_CLIENT_ID",
  "falcon_client_secret": "YOUR_CLIENT_SECRET",
  "base_url": "US1"
}
EOF
chmod 600 ~/.config/falcon/credentials.json
```

Valid `base_url` values: `US1`, `US2`, `EU1`, `GOV1`.

## 4. Import Your First Resources

If you already have detections, saved searches, or other resources in your CrowdStrike tenant, import them to bring them under IaC management.

### Preview the Import

```bash
python scripts/resource_deploy.py import --plan
```

This connects to your tenant, discovers existing resources, and shows what would be imported — without changing anything.

### Run the Import

```bash
# Import detection rules
python scripts/resource_deploy.py import --resources=detection

# Import saved searches
python scripts/resource_deploy.py import --resources=saved_search

# Import multiple types at once
python scripts/resource_deploy.py import --resources=detection,saved_search,workflow

# Import everything
python scripts/resource_deploy.py import
```

What happens:
- YAML templates are generated in `resources/<type>/` for each discovered resource
- The state file (`.crowdstrike/deployed_state.json`) is created/updated
- Each resource gets a stable `resource_id` — **never change this after import**

### Verify

```bash
# Check the generated templates
ls resources/detections/

# Validate all templates parse correctly
python scripts/resource_deploy.py validate

# Show current state
python scripts/resource_deploy.py show
```

## 5. Using the SOC Skill

Start Claude Code in the ClaudeStrike directory:

```bash
claude
```

The SOC skill activates via the `/soc` command:

```
/soc daily              # Review today's untriaged alerts
/soc daily endpoint     # Only endpoint alerts
/soc daily ngsiem       # Only NGSIEM correlation alerts
/soc triage <alert-id>  # Deep-dive a specific alert
/soc hunt <description> # Threat hunting with IOCs or hypothesis
/soc tune <detection>   # Tune a detection for false positives
```

### What to Expect

**Daily mode** (`/soc daily`):
1. Loads environmental context and memory files
2. Fetches untriaged alerts by product category
3. Assigns triage depth tiers (fast-track, pattern-match, standard, deep)
4. Presents a summary table and waits for you to pick which alerts to investigate
5. Walks through triage for each selected alert
6. Proposes classification (TP/FP) and waits for your approval before closing

**Single alert triage** (`/soc triage <id>`):
1. Loads the matching investigation playbook
2. Calls `alert_analysis` for enriched alert data
3. Runs investigation queries (CQL, host lookup, cloud asset checks)
4. Presents evidence and classification
5. If FP: proposes detection tuning with a diff
6. If TP: generates escalation package with timeline, scope, IOCs, and hunting queries

The skill never closes an alert without your confirmation.

### MCP Server Requirement

The SOC skill depends on CrowdStrike MCP tools being available in your Claude Code session. You need to configure a CrowdStrike MCP server in your `.mcp.json` (project root or `~/.claude/.mcp.json`):

```json
{
  "mcpServers": {
    "crowdstrike": {
      "command": "path/to/your/mcp/server",
      "args": ["--config", "path/to/config"]
    }
  }
}
```

The specific MCP tools used by the SOC skill:
- `ngsiem_query` — execute CQL queries
- `get_alerts` — retrieve alerts with filters
- `alert_analysis` — deep-dive enrichment on a single alert
- `update_alert_status` — close/tag alerts
- `host_lookup` — device posture
- `host_login_history`, `host_network_history` — host context
- `cloud_query_assets`, `cloud_get_iom_detections`, `cloud_get_risks` — cloud security
- `case_create`, `case_update`, `case_add_alert_evidence` — case management

## 6. Customizing Skills

### Environmental Context

Edit `.claude/skills/soc-v1/environmental-context.md` (or the v2/v3 equivalent) to teach the SOC skill about your environment:

- **Known service accounts** — so it doesn't flag them as suspicious
- **Expected IP ranges** — VPN, office, CI/CD runner IPs
- **Business context** — what's normal in your org (deployment windows, admin patterns)
- **Cloud accounts** — account IDs, names, trust relationships
- **User groups** — admin groups, service teams, automation accounts

The more context you provide, the fewer false positives and the better the triage quality.

### Memory Files

Memory files in `memory/` (v2/v3) or single-file `MEMORY.md` (v1) accumulate institutional knowledge:

| File | What Goes Here |
|------|---------------|
| `fp-patterns.md` | Known false positive signatures with specific IOCs |
| `tp-patterns.md` | Confirmed true positive indicators |
| `fast-track-patterns.md` | High-confidence bulk-close patterns (must be 100% noise) |
| `investigation-techniques.md` | CQL query patterns, field gotchas, repo mapping |
| `tuning-log.md` | History of tuning decisions with rationale |
| `tuning-backlog.md` | Pending tuning work |
| `detection-ideas.md` | New detection concepts discovered during triage |

These start empty. They fill up organically as you triage alerts — the skill proposes updates after each session.

### Playbooks

Investigation playbooks in `playbooks/` guide the skill through specific alert types:

- `cloud-security-aws.md` — AWS CloudTrail and cloud security alerts
- `entraid-signin-alert.md` — EntraID sign-in third-party alerts
- `entraid-risky-signin.md` — EntraID risky sign-in NGSIEM detections
- `knowbe4-phisher.md` — KnowBe4 PhishER alerts
- `container-sensor-investigation.md` — container/ECS sensor questions

Add your own playbooks for alert types specific to your environment.

## 7. CI/CD Setup

Two GitHub Actions workflows are included in `.github/workflows/`:

### plan-and-deploy.yml

- **Trigger:** PR opened/updated, or push to `main`
- **PR behavior:** Runs `plan`, posts summary as PR comment
- **Main branch behavior:** Runs `apply --auto-approve`

### Required GitHub Secrets

| Secret | Value |
|--------|-------|
| `FALCON_CLIENT_ID` | Your CrowdStrike API client ID |
| `FALCON_CLIENT_SECRET` | Your CrowdStrike API client secret |
| `FALCON_BASE_URL` | Your cloud region (e.g., `US1`, `US2`, `EU1`) |

Set these in your GitHub repo under **Settings > Secrets and variables > Actions**.

### weekly-template-discovery.yml

Runs weekly to discover new resource templates that may have been added outside the IaC workflow. Helpful for catching drift.

## 8. Troubleshooting

### Authentication Errors

```
Error: Authentication failed (401)
```

- Verify credentials: `cat ~/.config/falcon/credentials.json`
- Check your cloud region matches your tenant
- Ensure the API client hasn't been revoked in the Falcon Console
- Re-run `python scripts/setup.py` to reconfigure

### Import Finds No Resources

```
No resources found for type: detection
```

- Confirm your API client has the required scopes (Custom IOA Rules: Read)
- Check that you're pointing at the right tenant/region
- Try `python scripts/resource_deploy.py import --plan` to see the full discovery output

### MCP Tools Not Available

If `/soc` can't find CrowdStrike MCP tools:
- Verify your `.mcp.json` has a `crowdstrike` server configured
- Check that the MCP server process is running
- Restart Claude Code to reload MCP server connections
- Check `enabledMcpjsonServers` in `.claude/settings.local.json` includes `"crowdstrike"`

### Plan Shows Unexpected Changes

```
~ update detection: my-detection (content changed)
```

- Someone may have edited the detection in the Falcon Console directly
- Run `python scripts/resource_deploy.py drift` to see what changed
- Run `python scripts/resource_deploy.py sync` to pull the live version into state
- Decide whether to keep the console change (update template) or revert it (apply)

### Saved Search Description Too Long

```
Error: Description exceeds 2000 character limit
```

The CrowdStrike API silently truncates saved search descriptions beyond 2000 characters. Keep descriptions concise. The validate command catches this before deployment.

### Tests

```bash
# Run all tests
pytest

# Run a specific test
pytest tests/unit/test_detection_provider.py -v
```
