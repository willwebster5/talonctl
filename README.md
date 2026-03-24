# ClaudeStrike

Claude Code skills for CrowdStrike NG-SIEM — AI-assisted SOC operations and detection engineering as code.

## What This Is

I'm a security engineer who's been using Claude Code as my SOC co-pilot for the past year. This repo is the skills, playbooks, and IaC system I've built over months of daily alert triage, detection writing, and incident response.

It's a work in progress. I'm sharing it because people asked and I dont feel like im getting enough use out of it in my small deployment.

What you get:
- **A ReadMe I de-AI** - Gosh I can see AI writing from a mile away, It helped me put everything together for this repo but I will edit the readme now
- **AI SOC analyst skills** — three iterations of a skill that triages CrowdStrike alerts, investigates threats, hunts for IOCs, and tunes detections (This is major WIP, it uses an MCP to interact with crowdstrike, with modular tooling so you dont have to give it any write permissions and I'd recommend not in production obviously)
- **Terraform-like deployment** — This is sorta the engine that the skills work off of.  plan/apply/import/drift for NGSIEM resources (detections, saved searches, workflows, lookup files, RTR scripts).  It provides your AI Agent a searchable index of your CS Environment, and has the added benefit of allowing IaC management as well.
- **CI/CD workflows** — GitHub Actions for automated plan-on-PR, apply-on-merge
- **Behavioral detection patterns** — attack chain templates for writing correlation rules across AWS, EntraID, endpoint, and more
- **CQL query library** — patterns for aggregation, correlation, scoring, baselining, and enrichment in LogScale/NG-SIEM


## Prerequisites

- CrowdStrike Falcon tenant with NG-SIEM (LogScale)
- [Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code)
- Python 3.11+
- CrowdStrike API credentials (Falcon Console > Support & Resources > API Clients and Keys)
- A CrowdStrike MCP server (for the SOC skill to query alerts and run CQL — see [crowdstrike-mcp](https://github.com/CrowdStrike/foundry-sample-rapid-response) or build your own)

## Quick Start

```bash
# Clone
git clone https://github.com/yourusername/ClaudeStrike.git
cd ClaudeStrike

# Install dependencies
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Configure credentials
python scripts/setup.py

# Import your existing detections
python scripts/resource_deploy.py import --plan              # preview what would be imported
python scripts/resource_deploy.py import --resources=detection  # import detection rules

# Start using the SOC skill
claude   # start Claude Code in this directory
/soc daily   # review today's untriaged alerts
```

## Project Structure

```
ClaudeStrike/
├── .claude/
│   ├── commands/                  # Slash commands: /soc, /research, /discuss
│   └── skills/
│       ├── soc-v1/                # Battle-tested daily driver
│       ├── soc-v2/                # Experimental: phased memory loading
│       ├── soc-v3/                # Experimental: agent-delegated architecture
│       ├── behavioral-detections/ # Attack chain rule patterns
│       ├── cql-patterns/          # CQL query pattern library
│       ├── detection-tuning/      # FP tuning with enrichment function catalog
│       ├── fusion-workflows/      # Falcon Fusion workflow templates
│       ├── logscale-security-queries/  # LogScale query reference
│       └── soc-workspace/         # Eval harness and iteration history
├── .crowdstrike/                  # State files (deployed_state.json)
├── .github/workflows/             # CI/CD: plan on PR, apply on merge
├── resources/                     # IaC templates (your detections live here)
│   ├── detections/                # Correlation rules
│   ├── saved_searches/            # Reusable CQL functions
│   ├── workflows/                 # Falcon Fusion workflows
│   ├── lookup_files/              # CSV lookup tables
│   ├── rtr_scripts/               # Real Time Response scripts
│   └── rtr_put_files/             # RTR file deployments
├── scripts/                       # Deployment engine
│   ├── resource_deploy.py         # Main CLI (plan/apply/import/drift/sync)
│   ├── setup.py                   # Credential setup wizard
│   ├── core/                      # Orchestrator, state manager, drift detector
│   └── providers/                 # Per-resource-type API adapters
├── tests/                         # Unit tests
└── examples/                      # Dashboards, parsers, lookup templates
```

## The Skills

### SOC Skill (v1) — Daily Driver

The skill I actually use every day. Unified alert lifecycle: triage, investigate, classify, close, tune.

```
/soc daily              # batch triage today's alerts
/soc triage <alert-id>  # deep-dive a specific alert
/soc hunt <IOCs>        # threat hunting
/soc tune <detection>   # tune a detection for false positives
```

It loads environmental context and memory files (known FP/TP patterns, investigation techniques, tuning history), routes to the right playbook based on alert type, runs investigation queries via MCP tools, and presents a triage summary for human review. It never closes an alert without asking(Not true, definetly has closed a FP without asking before)

### SOC Skill (v2) — Experimental

Decomposes v1 into explicit phases with staged memory loading. The idea: don't load FP patterns until after you've collected evidence independently, so you avoid confirmation bias. Phases: Intake > Triage > Classify > Close > Tune.

### SOC Skill (v3) — Experimental

Agent-delegated architecture. Decomposes investigation into sub-agents (alert formatter, CQL query builder, MCP investigator, evidence summarizer). Still being evaluated. (Honestly not good, V2 probably is a sweet spot ill build off of, V3 Is VERY Eager to close out a detection on its own if its a confident FP, and it is not relying on its agents as much as I hoped, I think giving it an Orchestrator role has had side effects, I'm really just playing around with agentic capabilities, I wouldnt rely on this at all)

### Other Skills

- **behavioral-detections** — attack chain patterns for AWS, EntraID, endpoint. Templates for writing multi-stage correlation rules.
- **cql-patterns** — CQL query cookbook: aggregation, correlation, scoring, baselining, string/decode, enrichment, output formatting.
- **detection-tuning** — catalog of 38+ enrichment functions, tuning patterns, and FP resolution strategies.
- **fusion-workflows** — Falcon Fusion YAML schema, workflow templates, trigger/action reference.
- **logscale-security-queries** — LogScale query reference, investigation playbooks, troubleshooting.

### Commands

| Command | What It Does |
|---------|-------------|
| `/soc` | SOC operations (triage, daily, hunt, tune) |
| `/research` | Deep technical research with web search |
| `/discuss` | Exploratory discussion mode — no file changes |

## The IaC System

Terraform-like lifecycle for CrowdStrike NGSIEM resources.

```bash
python scripts/resource_deploy.py validate   # check templates
python scripts/resource_deploy.py plan       # preview changes
python scripts/resource_deploy.py apply      # deploy
python scripts/resource_deploy.py import     # onboard existing resources
python scripts/resource_deploy.py sync       # reconcile state with tenant
python scripts/resource_deploy.py drift      # detect manual console changes
python scripts/resource_deploy.py show       # display current state
```

### Import Command

Already have detections in your tenant? Import them:

```bash
# Preview what would be imported
python scripts/resource_deploy.py import --plan

# Import specific resource types
python scripts/resource_deploy.py import --resources=detection
python scripts/resource_deploy.py import --resources=saved_search,detection
```

This generates YAML templates in `resources/` and updates the state file, bringing existing resources under IaC management.

### CI/CD

GitHub Actions workflows included:
- **PR opened** — runs `plan`, posts a summary comment
- **Merge to main** — runs `apply --auto-approve`

Required secrets: `FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET`, `FALCON_BASE_URL`

## Required API Scopes

### IaC Engine — By Resource Type

| Resource Type | Read (plan/sync/drift/import) | Write (apply) |
|--------------|-------------------------------|---------------|
| Detection | `correlation-rules:read` | `correlation-rules:write` |
| Saved Search | `ngsiem:read` | `ngsiem:write` |
| Lookup File | `ngsiem:read` | `ngsiem:write` |
| Workflow | `workflow:read` | `workflow:write` |
| RTR Script | `real-time-response-admin:write` | `real-time-response-admin:write` |
| RTR Put File | `real-time-response-admin:write` | `real-time-response-admin:write` |

### IaC Engine — By Command

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

### SOC Skill (via MCP Server)

The SOC skills don't call the Falcon API directly — they use MCP tools provided by a [CrowdStrike MCP server](https://github.com/willwebster5/crowdstrike-mcp). See that repo's README for the full tool-to-scope mapping.

**Minimum for read-only triage:** `alerts:read`, `ngsiem:read`, `hosts:read`, `detects:read`

**With status updates and case management:** add `alerts:write`, `cases:read`, `cases:write`

### Minimum Scopes by Workflow

| Workflow | Scopes |
|----------|--------|
| **Just detections** (plan/apply) | `correlation-rules:read`, `correlation-rules:write` |
| **Detections + saved searches** | Above + `ngsiem:read`, `ngsiem:write` |
| **Full IaC** (all resource types) | All read + write scopes above |
| **Import only** (onboarding) | Read scopes for target resource types |
| **SOC triage** (read-only) | `alerts:read`, `ngsiem:read`, `hosts:read`, `detects:read` |
| **SOC triage + close/tune** | Above + `alerts:write`, `correlation-rules:read`, `correlation-rules:write` |

### Setup Script

`python scripts/setup.py` uses `sensor-installers:read` to validate credentials. This scope is only needed for the one-time setup check.

## License

MIT — do whatever you want, no warranty, no liability. See [LICENSE](LICENSE).
