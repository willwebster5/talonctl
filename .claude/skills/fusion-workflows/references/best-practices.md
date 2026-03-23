# Fusion Workflow Best Practices

Operational guidance for CrowdStrike Fusion workflow authoring,
supplemented by official CrowdStrike recommendations.

---

## IaC deployment model

Workflows are saved to `resources/workflows/<vendor>/` and deployed via `resource_deploy.py plan/apply`.
The fusion-workflows skill does not deploy directly — it authors and validates YAML only.

Deployment workflow:
1. Author YAML with this skill (save to `resources/workflows/<vendor>/`)
2. Validate with `validate.py`
3. Run `python scripts/resource_deploy.py plan --resources=workflow` to preview
4. Run `python scripts/resource_deploy.py apply --resources=workflow` to deploy

See `config/workflow_config.yaml` for Slack channel IDs per vendor.

---

## Workflow design

### Start simple, then iterate
Build the simplest version first (single action, no loops). Validate it works
end-to-end before adding loops, conditions, or error handling.

### Use the loop pattern for bulk operations
For "do X to each item in a list", always use:
```
CreateVariable → Action → UpdateVariable
```
This collects per-iteration results into `WorkflowCustomVariable` and surfaces them
via `output_fields`. See `templates/loop.yaml` template.

### Use sequential loops unless parallelism is safe
Set `sequential: true` in the loop `for` block. Parallel execution (`sequential: false`)
can cause race conditions with rate-limited APIs or stateful operations like containment.

### Track results per iteration
Always create a `WorkflowCustomVariable` with enough fields to report success/failure
per item. Include the input value (e.g., `device_id`) so callers can correlate results.

---

## Action selection

### Containment actions
- **Contain device**: look up via `action_search.py --search "contain"`
- **Lift containment**: look up via `action_search.py --search "lift containment"`
- Containment maintains sensor connectivity — the host can still communicate with CrowdStrike

### IOC blocking vs. ThreatGraph lookup
- **Block** actions (hash/IP/domain) add indicators to the CrowdStrike IOC management system
- **Get devices associated with** actions query ThreatGraph for historical connections
- These serve different purposes: blocking prevents future access; ThreatGraph shows past exposure

### RTR (Real Time Response) actions
- RTR actions run commands on endpoints: process listing, file retrieval, memory dump
- They require an active sensor connection — if the host is offline, the action will fail
- Some RTR actions require elevated permissions (e.g., `runscript`, `put`)

### Third-party plugin actions
- Plugin actions (Okta, Entra ID, Mimecast, etc.) require:
  1. The plugin installed in the CrowdStrike Store
  2. A valid `config_id` for the plugin instance
- `config_id` values are **CID-specific** — they won't work across tenants
- Always search for the action via `action_search.py` to confirm availability

---

## version_constraint

### When to use it
- **Always** on `CreateVariable` and `UpdateVariable` (class-based actions)
- **Always** when the action response from `action_search.py --details` includes `class`
- **Sometimes** on catalog actions that have been versioned (check API response)

### The correct value
```yaml
version_constraint: ~1
```
This means "compatible with major version 1" (semver tilde range). All current
CrowdStrike actions use major version 1.

### What happens without it
Import validation fails with an error like:
```
version constraint required for activity class 'CreateVariable'
```

---

## YAML authoring gotchas

### Workflow names must be unique per CID
When re-importing a workflow, either:
- Delete the existing definition first, or
- Change the name in the YAML, or
- Use the `name` query parameter on the import endpoint to override

### PLACEHOLDER markers
Templates use `PLACEHOLDER_*` markers. The `validate.py` pre-flight check catches these.
Replace ALL markers before attempting API validation.

### Quoting in property templates
Property values use `${data['path']}` syntax. Be careful with YAML quoting:
```yaml
# CORRECT — YAML treats this as a plain string
device_id: ${data['device_id']}

# ALSO CORRECT — explicit quoting
device_id: "${data['device_id']}"

# WRONG — single-quoted YAML string eats the single quotes in data['...']
device_id: '${data[''device_id'']}'   # This works but is fragile
```

### Boolean and integer values in UpdateVariable
Set these as bare values (no `${}` wrapping) when they're constants:
```yaml
WorkflowCustomVariable:
    contained: true           # Boolean constant
    count: 0                  # Integer constant
    device_id: ${data['id']}  # Dynamic value
```

### The null/"0" coercion in loops
The workflow engine silently converts null/missing fields to the string `"0"`.
When using custom variables for loop control (pagination), check both:
```
WorkflowCustomVariable.next:!null+WorkflowCustomVariable.next:!'0'
```

---

## Import/export considerations

### Import restrictions
Workflows **cannot** be imported if they use:
- Third-party plugin actions with CID-specific `config_id` values (from a different CID)
- Falcon Foundry template actions
- CID-specific event queries from a different CID

### Export restrictions
Workflows created from Falcon Foundry workflow templates **cannot** be exported.

### Testing before production import
Always validate first:
```bash
python .claude/skills/fusion-workflows/scripts/validate.py workflow.yaml
```
This runs both pre-flight checks and API dry-run validation (`validate_only=true`).

---

## Execution and monitoring

### Use mock executions for testing
`POST /workflows/entities/mock-executions/v1` lets you test with fake trigger and
action data without affecting real systems. Use this for event-triggered workflows
that can't be tested with the execute endpoint.

### Execution statuses
| Status | Meaning |
|--------|---------|
| `In progress` | Still running |
| `Succeeded` | Completed successfully |
| `Failed` | One or more actions failed |
| `ActionRequired` | Waiting for human input |
| `Canceled` | Manually canceled |
| `NonRecoverable` | Permanent failure |

### Rate limiting
CrowdStrike API: 6,000 requests/minute per CID. This applies to all workflow API
calls including executions. Bulk operations should use sequential loops to stay within limits.

---

## Working with third-party integrations

### Identifying plugin vs native actions
- **Native actions** have `vendor: "CrowdStrike"` or a namespace like `containment`, `identity_protection.*`, `faas`
- **Plugin actions** have a third-party vendor (Okta, Microsoft, Netskope, etc.) and typically `namespace: "plugin.custom_integration"`
- Use `action_search.py --details <id>` to see the vendor, namespace, and plugin flag
- Use `action_search.py --vendors` to browse all available integrations and their action counts

### Finding config_id for plugin actions
Plugin actions require a `config_id` that identifies the configured integration instance:
1. Go to Falcon console → CrowdStrike Store → find the app (e.g., "Okta")
2. Open the app → Integration settings
3. Copy the config ID for the configured instance
4. Add it to the workflow YAML action properties:
```yaml
properties:
  config_id: "your-config-id-here"
  # ... other action properties
```
- `config_id` values are **CID-specific** — they won't transfer across tenants

### Common integration patterns
- **Okta session revocation**: Search `--vendor "Okta" --search "revoke"` — revoke user sessions during incident response
- **Entra ID group management**: Search `--vendor "Microsoft" --search "group"` — add/remove users from security groups
- **Netskope URL blocking**: Search `--vendor "Netskope" --search "url"` — block malicious URLs in Netskope
- **Zscaler block list**: Search `--vendor "Zscaler" --search "block"` — add IOCs to Zscaler block lists

### has_permission: false
When `action_search.py --details` shows `Permission: NOT AVAILABLE`, it means:
- The CrowdStrike Store app for that vendor is **not installed** in your CID, or
- The app is installed but **not configured** (missing integration settings), or
- Your API client credentials lack the required scope

Install and configure the app in the CrowdStrike Store before using those actions in workflows.

---

## Workflow limits

| Limit | Value |
|-------|-------|
| Loop iterations | 100,000 max |
| Execution window | 7 days max |
| Function call timeout | 15 minutes |
| API rate limit | 6,000 req/min per CID |
| HTTP action response | 10 MB max, must be JSON object |
