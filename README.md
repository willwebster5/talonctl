# talonctl

Infrastructure as code for CrowdStrike. Manage detections, workflows, saved searches, and more with a Terraform-like lifecycle.

## What This Is

I'm a security engineer who built this to manage my CrowdStrike tenant as code. It started as the deployment engine behind an AI-assisted SOC project and works just as well standalone. If you use CrowdStrike NG-SIEM and want version-controlled, CI/CD-deployed resources — this is it.

What you get:
- **Terraform-like deployment** — plan/apply/import/drift/sync for CrowdStrike NGSIEM resources
- **Seven resource types** — detections, saved searches, dashboards, workflows, lookup files, RTR scripts, RTR put files
- **CI/CD workflows** — GitHub Actions for automated plan-on-PR, apply-on-merge
- **State management** — tracks deployed resources, content hashes, and CrowdStrike API IDs
- **Dependency resolution** — DAG-based ordering so resources deploy in the right sequence
- **Drift detection** — catch manual console changes that diverge from your templates

## What It Manages

| Resource Type | Template Dir | Description |
|--------------|-------------|-------------|
| Detection | `resources/detections/` | Correlation rules (CQL queries with severity, MITRE mapping) |
| Saved Search | `resources/saved_searches/` | Reusable CQL functions called with `$function_name()` |
| Dashboard | `resources/dashboards/` | LogScale dashboards with sections and widgets |
| Workflow | `resources/workflows/` | Falcon Fusion automation workflows |
| Lookup File | `resources/lookup_files/` | CSV lookup tables for enrichment |
| RTR Script | `resources/rtr_scripts/` | Real Time Response scripts |
| RTR Put File | `resources/rtr_put_files/` | Files pushed to endpoints via RTR |

## Project Structure

```
talonctl/
├── .crowdstrike/              # State files (deployed_state.json)
├── .github/workflows/         # CI/CD: plan on PR, apply on merge
├── resources/                 # IaC templates
│   ├── detections/
│   ├── saved_searches/
│   ├── dashboards/
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

## Prerequisites

- CrowdStrike Falcon tenant with NG-SIEM (LogScale)
- Python 3.11+
- CrowdStrike API credentials (Falcon Console > Support & Resources > API Clients and Keys)

## Quick Start

```bash
# Clone
git clone https://github.com/willwebster5/talonctl.git
cd talonctl

# Install dependencies
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Configure credentials
python scripts/setup.py

# Import your existing detections
python scripts/resource_deploy.py import --plan              # preview what would be imported
python scripts/resource_deploy.py import --resources=detection  # import detection rules

# Plan and deploy
python scripts/resource_deploy.py plan    # preview changes
python scripts/resource_deploy.py apply   # deploy
```

## Commands

```bash
python scripts/resource_deploy.py validate       # check templates (no API calls)
python scripts/resource_deploy.py plan            # preview changes
python scripts/resource_deploy.py apply           # deploy changes
python scripts/resource_deploy.py import          # onboard existing resources
python scripts/resource_deploy.py import --plan   # preview import
python scripts/resource_deploy.py sync            # reconcile state with tenant
python scripts/resource_deploy.py drift           # detect manual console changes
python scripts/resource_deploy.py show            # display current state
```

## Import

Already have detections in your tenant? Import them:

```bash
# Preview what would be imported
python scripts/resource_deploy.py import --plan

# Import specific resource types
python scripts/resource_deploy.py import --resources=detection
python scripts/resource_deploy.py import --resources=saved_search,detection

# Import everything
python scripts/resource_deploy.py import
```

This generates YAML templates in `resources/` and updates the state file, bringing existing resources under IaC management.

## CI/CD

GitHub Actions workflows included:

- **PR opened** — runs `plan`, posts a summary comment with what would change
- **Merge to main** — runs `apply --auto-approve` to deploy
- **Weekly** — template discovery for new CrowdStrike OOTB content

Required secrets: `FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET`, `FALCON_BASE_URL`

## Required API Scopes

### By Resource Type

| Resource Type | Read (plan/sync/drift/import) | Write (apply) |
|--------------|-------------------------------|---------------|
| Detection | `correlation-rules:read` | `correlation-rules:write` |
| Saved Search | `ngsiem:read` | `ngsiem:write` |
| Dashboard | `ngsiem:read` | `ngsiem:write` |
| Lookup File | `ngsiem:read` | `ngsiem:write` |
| Workflow | `workflow:read` | `workflow:write` |
| RTR Script | `real-time-response-admin:write` | `real-time-response-admin:write` |
| RTR Put File | `real-time-response-admin:write` | `real-time-response-admin:write` |

### By Command

| Command | Required Scopes | Notes |
|---------|----------------|-------|
| `validate` | None | Local-only, no API calls |
| `plan` | Read scopes for managed resource types | Compares templates to remote state |
| `apply` | Read + Write scopes for managed resource types | Creates, updates, and deletes resources |
| `import` | Read scopes for target resource types | Fetches remote resources, writes local YAML |
| `sync` | Read scopes for managed resource types | Reconciles state file with remote |
| `drift` | Read scopes for managed resource types | Detects manual console changes |
| `show` | None | Reads local state file only |
| `validate-query` | `ngsiem:read` | Validates CQL syntax via API |

### Minimum Scopes by Workflow

| Workflow | Scopes |
|----------|--------|
| **Just detections** (plan/apply) | `correlation-rules:read`, `correlation-rules:write` |
| **Detections + saved searches** | Above + `ngsiem:read`, `ngsiem:write` |
| **Full IaC** (all resource types) | All read + write scopes above |
| **Import only** (onboarding) | Read scopes for target resource types |

### Setup Script

`python scripts/setup.py` uses `sensor-installers:read` to validate credentials. This scope is only needed for the one-time setup check.

## Ecosystem

talonctl was built alongside a set of AI-assisted security skills and a CrowdStrike MCP server. Together they form a detection engineering and SOC operations toolkit:

- **[agent-skills](https://github.com/willwebster5/agent-skills)** — Claude Code plugin marketplace with CrowdStrike skills for SOC triage, detection engineering, threat hunting, and more. The skills are designed to work on top of talonctl-managed resources.
- **[crowdstrike-mcp](https://github.com/willwebster5/crowdstrike-mcp)** — MCP server for querying alerts, running CQL, host lookup, and case management. Used by the agent-skills plugins.

To use talonctl with AI-assisted workflows: install the agent-skills plugins into Claude Code, point them at a talonctl-managed repo, and copy `CLAUDE.integrated.md` over `CLAUDE.md` for the full experience.

## License

MIT — do whatever you want, no warranty, no liability. See [LICENSE](LICENSE).
