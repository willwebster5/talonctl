# Getting Started

Detailed onboarding walkthrough for talonctl.

## 1. Prerequisites

You need:

- **CrowdStrike Falcon tenant** with NG-SIEM (LogScale) enabled
- **CrowdStrike API credentials** — create an API client in the Falcon Console:
  - Go to **Support & Resources > API Clients and Keys**
  - Create a new client with the scopes needed for your resource types (see README for scope reference)
- **Python 3.11+** — with pip
- **Git**

## 2. Installation

```bash
# Clone the repo
git clone https://github.com/willwebster5/talonctl.git
cd talonctl

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

## 5. Plan and Deploy

```bash
# See what would change
python scripts/resource_deploy.py plan

# Deploy (after reviewing the plan)
python scripts/resource_deploy.py apply
```

## 6. CI/CD Setup

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

Runs weekly to discover new CrowdStrike OOTB templates. Creates a PR with any new templates found for your review.

## 7. Using with AI Skills (Optional)

If you want AI-assisted SOC operations on top of talonctl, see the [agent-skills](https://github.com/willwebster5/agent-skills) repo. To set it up:

1. Install the agent-skills plugins into Claude Code
2. Copy the integrated instructions: `cp CLAUDE.integrated.md CLAUDE.md`
3. Configure a [CrowdStrike MCP server](https://github.com/willwebster5/crowdstrike-mcp) for live alert/query access

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
