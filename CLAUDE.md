# talonctl — Project Instructions

Infrastructure as code for CrowdStrike. Terraform-like plan/apply for NGSIEM resources.

## Project Overview

This repo provides a deployment engine for CrowdStrike NGSIEM resources:
- **Six resource types** — detections, saved searches, workflows, lookup files, RTR scripts, RTR put files
- **Terraform-like lifecycle** — validate, plan, apply, import, sync, drift
- **State management** — tracks deployed resources and their CrowdStrike API IDs
- **CI/CD** — GitHub Actions for plan-on-PR, apply-on-merge

## Critical Concepts

### resource_id vs name

Every IaC-managed resource has two identifiers:

- **`resource_id`** — stable key used by the state file to track the resource. Think of it like a Terraform resource address. Once deployed, **never change this**. Changing it after deployment = destroy + recreate.
- **`name`** — the display name visible in the Falcon console. Can be updated freely.

### State File

- Location: `.crowdstrike/deployed_state.json`
- Format version: v3.0
- Tracks all deployed resources, their content hashes, and CrowdStrike API IDs
- Do not edit manually — use `sync` to reconcile with the live tenant

## Common Commands

```bash
# Validate all templates (no API calls)
python scripts/resource_deploy.py validate

# Preview what would change
python scripts/resource_deploy.py plan

# Deploy changes (requires plan first)
python scripts/resource_deploy.py apply

# Import existing tenant resources into IaC
python scripts/resource_deploy.py import --plan          # preview
python scripts/resource_deploy.py import --resources=detection  # execute

# Sync state with live tenant
python scripts/resource_deploy.py sync

# Detect manual console changes
python scripts/resource_deploy.py drift

# Show current state
python scripts/resource_deploy.py show
```

## Production Rules

1. **Always plan before apply.** Never blind-deploy. CI/CD enforces this on PRs.
2. **Never change `resource_id` after deploy.** It destroys and recreates the resource.
3. **Saved search description limit: 2000 characters.** The API silently truncates beyond this.
4. **Validate CQL syntax** before committing detection changes: `python scripts/resource_deploy.py validate-query --template <path>`

## Resource Types

| Type | Template Dir | Description |
|------|-------------|-------------|
| Detection | `resources/detections/` | Correlation rules (CQL queries with severity, MITRE mapping) |
| Saved Search | `resources/saved_searches/` | Reusable CQL functions called with `$function_name()` |
| Workflow | `resources/workflows/` | Falcon Fusion automation workflows |
| Lookup File | `resources/lookup_files/` | CSV lookup tables for enrichment |
| RTR Script | `resources/rtr_scripts/` | Real Time Response scripts |
| RTR Put File | `resources/rtr_put_files/` | Files pushed to endpoints via RTR |

## Credentials

- **Location:** `~/.config/falcon/credentials.json`
- **Format:**
  ```json
  {
    "falcon_client_id": "...",
    "falcon_client_secret": "...",
    "base_url": "US1"
  }
  ```
- **Setup:** `python scripts/setup.py`
- **Never commit credentials.** The `.gitignore` excludes credential files.

## Project Structure

```
talonctl/
├── .crowdstrike/              # State files (deployed_state.json)
├── .github/workflows/         # CI/CD: plan on PR, apply on merge
├── resources/                 # IaC templates
│   ├── detections/
│   ├── saved_searches/
│   ├── workflows/
│   ├── lookup_files/
│   ├── rtr_scripts/
│   └── rtr_put_files/
├── scripts/                   # Deployment engine
│   ├── resource_deploy.py     # Main CLI
│   ├── setup.py               # Credential setup wizard
│   ├── core/                  # Orchestrator, state, plan, drift
│   ├── providers/             # Per-resource-type API adapters
│   └── utils/                 # Auth, NGSIEM client, MITRE processor
├── tests/                     # Unit tests
└── examples/                  # Dashboards, parsers, lookup file templates
```

## CI/CD

- **PR opened:** Runs `plan` and posts summary as PR comment
- **Merge to main:** Runs `apply --auto-approve`
- **Secrets required:** `FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET`, `FALCON_BASE_URL`
