# talonctl

Infrastructure as code for CrowdStrike. Manage detections, workflows, saved searches, and more with a Terraform-like lifecycle.

## What This Is

A pip-installable CLI tool for managing CrowdStrike NGSIEM resources as code. It started as the deployment engine behind an AI-assisted SOC project and works just as well standalone. If you use CrowdStrike NG-SIEM and want version-controlled, CI/CD-deployed resources -- this is it.

What you get:
- **Terraform-like deployment** -- plan/apply/import/drift/sync for CrowdStrike NGSIEM resources
- **Seven resource types** -- detections, saved searches, dashboards, workflows, lookup files, RTR scripts, RTR put files
- **State management** -- tracks deployed resources, content hashes, and CrowdStrike API IDs
- **Dependency resolution** -- DAG-based ordering so resources deploy in the right sequence
- **Drift detection** -- catch manual console changes that diverge from your templates
- **Project scaffolding** -- `talonctl init` creates new projects with the correct directory structure

## Getting Started

```bash
# Install
python3 -m venv .venv
source .venv/bin/activate
pip install talonctl

# Scaffold a new project
talonctl init myproject
cd myproject

# Configure credentials
talonctl auth setup

# Import your existing detections
talonctl import --plan              # preview what would be imported
talonctl import --resources=detection  # import detection rules

# Plan and deploy
talonctl plan    # preview changes
talonctl apply   # deploy
```

For a working example project, see [talonctl-demo](https://github.com/willwebster5/talonctl-demo).

## Commands

### IaC Lifecycle

```bash
talonctl validate                    # Check templates (no API calls)
talonctl plan                        # Preview changes
talonctl apply                       # Deploy changes
talonctl import                      # Onboard existing resources
talonctl import --plan               # Preview import
talonctl sync                        # Reconcile state with tenant
talonctl drift                       # Detect manual console changes
talonctl show                        # Display current state
talonctl init                        # Scaffold a new project
talonctl validate-query              # Validate CQL syntax
talonctl publish                     # Activate inactive detection rules
talonctl discover                    # Find new detection templates
```

### Credential Management

```bash
talonctl auth setup                  # Interactive credential setup wizard
talonctl auth check                  # Verify stored credentials
```

### Operational

```bash
talonctl health                      # Detection health check
talonctl health --format json -o r.json  # Export health report
talonctl metrics update-detections --report r.json  # Update detection metrics CSV
talonctl metrics update-kpis --report r.json        # Update KPI CSV
talonctl backup create               # Create state backup (GitHub Release)
talonctl backup list                 # List available backups
talonctl backup restore <tag>        # Restore from backup
```

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

## Prerequisites

- CrowdStrike Falcon tenant with NG-SIEM (LogScale)
- Python 3.11+
- CrowdStrike API credentials (Falcon Console > Support & Resources > API Clients and Keys)

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

### Minimum Scopes by Workflow

| Workflow | Scopes |
|----------|--------|
| **Just detections** (plan/apply) | `correlation-rules:read`, `correlation-rules:write` |
| **Detections + saved searches** | Above + `ngsiem:read`, `ngsiem:write` |
| **Full IaC** (all resource types) | All read + write scopes above |
| **Import only** (onboarding) | Read scopes for target resource types |

## Ecosystem

talonctl was built alongside a set of AI-assisted security skills and a CrowdStrike MCP server. Together they form a detection engineering and SOC operations toolkit:

- **[talonctl-demo](https://github.com/willwebster5/talonctl-demo)** -- Working example project with saved searches, lookup files, knowledge base, and CI/CD workflows
- **[agent-skills](https://github.com/willwebster5/agent-skills)** -- Claude Code plugins for SOC triage, detection engineering, threat hunting, and more
- **[crowdstrike-mcp](https://github.com/willwebster5/crowdstrike-mcp)** -- MCP server for querying alerts, running CQL, host lookup, and case management

## Development

```bash
git clone https://github.com/willwebster5/talonctl.git
cd talonctl
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
pytest tests/ -v
```

Format reference templates are in `examples/resources/` -- annotated YAML examples for every resource type.

## License

MIT -- do whatever you want, no warranty, no liability. See [LICENSE](LICENSE).
