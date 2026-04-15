# talonctl-demo — Showcase Repository

> **Status:** Approved
> **Date:** 2026-04-14
> **Scope:** New repo (talonctl-demo)
> **Dependencies:** talonctl pip packaging, crowdstrike-mcp pip packaging, agent-skills polish

## Goal

Create a showcase repository that demonstrates AI-assisted detection-as-code using all three tools together: talonctl (IaC engine), crowdstrike-mcp (API bridge), and agent-skills (Claude Code plugins). The demo features a fictional company with realistic infrastructure, seeded with generic detection rules that grow over time.

## Fictional Environment: Pinnacle Technology

A cloud-native SaaS startup (~200 engineers, ~50 with prod access).

**Technology stack:**
- **Cloud:** AWS (primary) — EC2, S3, Lambda, CloudTrail, GuardDuty
- **Identity:** EntraID (SSO for all services, Conditional Access policies)
- **Source control:** GitHub (organization audit logs enabled)
- **Collaboration:** Google Workspace (email, docs, drive)
- **Security:** CrowdStrike Falcon sensor on all endpoints, NGSIEM for log aggregation, Fusion for automation
- **Key data sources in NGSIEM:** CloudTrail, EntraID sign-in/audit logs, GitHub audit logs, Google Workspace activity, Falcon endpoint telemetry, network flow logs (VPC Flow Logs)

**Team structure:**
- Security team of 5 (1 manager, 2 detection engineers, 2 SOC analysts)
- DevOps/SRE team of 8 (relevant for CI/CD and infra alert noise)
- Engineering uses GitHub Actions for CI/CD, Terraform for infra

## Repository Structure

```
talonctl-demo/
├── .mcp.json                          # CrowdStrike MCP server config
├── .claude/
│   └── settings.json                  # agent-skills plugin references
├── CLAUDE.md                          # Integrated project instructions
├── README.md                          # "AI-assisted detection engineering demo"
├── LICENSE                            # MIT
│
├── knowledge/                         # Fully populated for Pinnacle
│   ├── INDEX.md                       # Routing table
│   ├── context/
│   │   └── environmental-context.md   # Pinnacle's stack, team, data sources
│   ├── patterns/
│   │   ├── aws.md                     # AWS FP/TP patterns for Pinnacle
│   │   ├── entraid.md                 # EntraID patterns
│   │   ├── github.md                  # GitHub audit log patterns
│   │   └── google.md                  # Google Workspace patterns
│   ├── techniques/
│   │   └── investigation-techniques.md
│   ├── tuning/
│   │   ├── tuning-backlog.md
│   │   └── tuning-log.md
│   ├── metrics/
│   │   └── detection-metrics.jsonl    # Empty — grows through use
│   ├── hunts/                         # Empty — grows through use
│   └── ideas/
│       └── detection-ideas.md
│
├── resources/
│   ├── detections/                    # Seed detections (generic, non-proprietary)
│   │   ├── generic_network_tor_traffic.yaml
│   │   └── (2-3 more generic rules)
│   ├── saved_searches/                # 1-2 reusable CQL functions
│   └── dashboards/                    # Optional: 1 SOC overview dashboard
│
├── .crowdstrike/
│   └── deployed_state.json            # Empty initial state
│
└── .gitignore
```

## Content Details

### CLAUDE.md

The integrated version — assumes talonctl is installed as a CLI, agent-skills plugins are available, and MCP server is configured. Includes:
- talonctl CLI commands (not `python scripts/resource_deploy.py`)
- Knowledge base schema and tiered loading
- ADS metadata documentation
- Detection metrics JSONL format
- Tuning log format
- Agent-skills command reference (/soc, /hunt, /research, /discuss)

### .mcp.json

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

### environmental-context.md

Describes Pinnacle Technology's infrastructure in enough detail for the SOC skill to make informed decisions:
- Company profile and business context
- Cloud architecture (AWS accounts, regions, key services)
- Identity provider setup (EntraID tenant, SSO apps, Conditional Access)
- Source control (GitHub org, key repos, CI/CD patterns)
- Data sources flowing into NGSIEM with expected log volumes
- Known noise sources (CI/CD service accounts, scheduled tasks, dev environments)
- Key contacts and escalation paths (fictional names)
- Compliance requirements (SOC 2, basic security program)

### Seed Detections

Start with 3-5 generic, non-proprietary detection rules:

1. **TOR traffic detection** — Already exists as `examples/resources/detection.yaml` in talonctl. Copy and adapt.
2. **2-3 additional generic rules** from your day-to-day work as they become available.

Each detection includes a full `ads:` block demonstrating the ADS metadata schema.

Rules added over time must be:
- Generic (not tied to a specific customer environment)
- Non-proprietary (no customer names, internal IPs/domains, or internal tool names). Public service names are fine (AWS CloudTrail, EntraID, GitHub). What's not OK: customer org names, internal hostnames like `prod-api-01`, proprietary tool names.
- Complete (valid CQL, full ADS metadata, MITRE mapping)

### Knowledge Base Population

The knowledge base files are populated with realistic but fictional content for Pinnacle:

- **INDEX.md:** Lists all detection rule IDs, last-updated dates, and current status
- **patterns/*.md:** Start mostly empty with headers and format documentation. Content grows through triage sessions.
- **environmental-context.md:** Fully populated with Pinnacle's infrastructure details
- **investigation-techniques.md:** Generic investigation patterns (not environment-specific)
- **tuning-backlog.md / tuning-log.md:** Start empty, formatted with headers
- **detection-ideas.md:** Seed with 2-3 detection concepts tied to Pinnacle's stack

### README.md

Targets: security engineers curious about detection-as-code + AI.

Sections:
1. **What this is** — A working example of AI-assisted detection engineering
2. **The tools** — Brief description of talonctl, crowdstrike-mcp, agent-skills with links
3. **Prerequisites** — CrowdStrike tenant, Python 3.11+, Claude Code
4. **Quick start** — Install tools, clone demo, configure credentials, run your first `talonctl plan`
5. **How it works** — The detection-as-code lifecycle with AI assistance
6. **Trying the AI workflows** — Example `/soc triage`, `/hunt hypothesis`, detection writing session
7. **Adding your own detections** — How to contribute generic rules
8. **Links** — talonctl, crowdstrike-mcp, agent-skills repos

## What This Repo Is NOT

- Not a production tenant configuration (no real resource IDs or API IDs)
- Not a detection rule library (it's a showcase of the *workflow*, rules are illustrative)
- Not a fork of talonctl (it's a *user* of talonctl, like a Terraform config is a user of Terraform)

## Growth Model

The demo repo grows organically, maintained by the repo owner (not crowdsourced):
1. Generic detection rules written during day-to-day SOC work get added to `resources/detections/`
2. Triage sessions against the demo environment build up `knowledge/patterns/` and `knowledge/metrics/`
3. Hunt reports from `/hunt` sessions land in `knowledge/hunts/`
4. Each addition makes the demo more realistic and useful as a reference

No pressure to front-load content. The value is in the *structure and workflow*, not the volume of rules.

## Out of Scope

- GitHub Actions CI/CD (users can add talonctl's workflows if they want)
- Real CrowdStrike API IDs in state file (state starts empty)
- Multiple environment configs (dev/staging/prod)
- Custom talonctl providers or plugins
