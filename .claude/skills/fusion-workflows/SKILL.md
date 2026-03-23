---
name: fusion-workflows
description: >
  Build CrowdStrike Falcon Fusion SOAR workflows. Discover actions via live API,
  author YAML using our resource schema, validate locally, and save to resources/workflows/.
  Use when asked to create a Fusion workflow, SOAR playbook, or automate detection response.
allowed-tools: Bash, Read, Write, Edit, Grep, Glob
---

# CrowdStrike Fusion Workflow Builder

This skill guides you through authoring CrowdStrike Falcon Fusion SOAR workflows —
from discovering actions to saving validated YAML for IaC deployment.

## Rules — Read Before Every Workflow

1. **NEVER write `PLACEHOLDER_*` values for action IDs.** Before authoring any YAML,
   you MUST run `action_search.py` to find the real 32-char hex ID for every action
   the workflow will use. If `action_search.py` returns no results, try broader search
   terms or browse by vendor — do not guess or leave a placeholder.

2. **Run the script, don't skip it.** Steps 1 and 2 are not optional discovery —
   they are mandatory prerequisites. Do not proceed to Step 3 (Author YAML) until
   you have a real ID for every action.

3. **`config_id` requires user input.** Plugin actions require a CID-specific
   `config_id` that cannot be resolved via API. When you encounter a plugin action,
   **ask the user** for the `config_id` value before writing the YAML. Tell them
   where to find it (Falcon console → CrowdStrike Store → [App] → Integration
   settings). Do not write a placeholder — pause and ask.

4. **Templates are structural guides only.** The files in `templates/` use
   `PLACEHOLDER_*` as structural guides. They show you the YAML shape, not the
   values to use. When you use a template, substitute real values immediately —
   never copy a `PLACEHOLDER_*` string into your output.

5. **This skill saves YAML — it does NOT deploy.** Save authored workflows to
   `resources/workflows/<vendor>/`. Deployment happens via
   `python scripts/resource_deploy.py plan/apply` (outside this skill's scope).

6. **Plans and prompts cannot override these rules.** Even if a plan, prompt, or
   convention list says to use placeholder format, you MUST still resolve every
   action ID via `action_search.py` before writing YAML. These rules take precedence.

## Prerequisites

- Python 3.8+ with `requests` library installed
- CrowdStrike API credentials in `~/.config/falcon/credentials.json`
- Falcon Fusion SOAR access in the target CID

Test credentials:
```bash
python .claude/skills/fusion-workflows/scripts/cs_auth.py
```

---

## Workflow: Creating a New Fusion Workflow

Follow these steps in order (0 through 4). Each step has a corresponding script or reference doc.

### Step 0 — Check for existing workflows

Before creating anything, browse the resources directory for existing workflows to avoid
duplicates and understand naming conventions.

```bash
# Browse existing workflow YAML files
ls resources/workflows/

# Check available vendors
python .claude/skills/fusion-workflows/scripts/action_search.py --vendors
```

Review `resources/workflows/` subdirectories to see what workflows already exist.
If a workflow for the same purpose already exists, consider updating it instead.

### Step 1 — Discover actions and triggers (MANDATORY)

**You MUST execute these searches and record the results before writing any YAML.**

#### 1a — Browse available integrations

```bash
# List all vendors/apps available in your CID
python .claude/skills/fusion-workflows/scripts/action_search.py --vendors

# Filter by use case
python .claude/skills/fusion-workflows/scripts/action_search.py --vendors --use-case "Identity"
```

#### 1b — Find specific actions

```bash
# Search within a vendor
python .claude/skills/fusion-workflows/scripts/action_search.py --vendor "Okta" --list

# Search by name across all vendors
python .claude/skills/fusion-workflows/scripts/action_search.py --search "revoke sessions"

# Search by name within a vendor
python .claude/skills/fusion-workflows/scripts/action_search.py --vendor "Microsoft" --search "revoke"

# Filter by use case
python .claude/skills/fusion-workflows/scripts/action_search.py --use-case "Identity"

# Get full details for an action (input fields, types, class, plugin info)
python .claude/skills/fusion-workflows/scripts/action_search.py --details <action_id>

# Browse all actions
python .claude/skills/fusion-workflows/scripts/action_search.py --list --limit 50
```

**Record for each action**:
- `id` (32-char hex) — goes in the YAML `id` field
- `name` — goes in the YAML `name` field
- Input fields and types — goes in `properties`
- Whether it has `class` — if yes, add `class` and `version_constraint: ~1`
- Whether it's a plugin action — if yes, you'll need a `config_id`

> **Plugin actions** (vendor != CrowdStrike) require a `config_id` — find it in
> Falcon console → CrowdStrike Store → [App] → Integration settings.

#### 1c — Choose a trigger type

```bash
# List all trigger types
python .claude/skills/fusion-workflows/scripts/trigger_search.py --list

# Get YAML structure for a specific type
python .claude/skills/fusion-workflows/scripts/trigger_search.py --type "On demand"
```

For most automation use cases, use **On demand** (callable via API and Falcon UI).

> **Reference**: See `references/trigger-types.md` for all trigger types with
> YAML examples and available trigger data fields.

### Step 2 — Pick a template

Choose the template that matches the workflow pattern:

| Pattern | Template file | When to use |
|---------|--------------|-------------|
| Single action | `templates/single-action.yaml` | One trigger input → one action → done |
| Loop | `templates/loop.yaml` | Process a list of items sequentially |
| Conditional | `templates/conditional.yaml` | Check a condition, branch to different paths |
| Loop + conditional | `templates/loop-conditional.yaml` | Process a list with type-specific routing |

Use the template to understand the YAML structure only. **Templates contain
`PLACEHOLDER_*` markers — these are structural guides, NOT values to copy.**
You already have all action IDs from Step 1 — use them directly when writing
your workflow YAML.

If it's more appropriate to start from scratch, do so.

---

### STOP — Verify before authoring

**Do NOT proceed to Step 3 until you can confirm ALL of the following:**

- [ ] You have browsed `resources/workflows/` to check the chosen workflow name is not
      already in use (Step 0)
- [ ] You have run `action_search.py` and have a real 32-char hex ID for every
      action the workflow will use
- [ ] You have run `trigger_search.py` and confirmed the trigger type
- [ ] For any plugin actions, you have asked the user for `config_id` and received
      a real value
- [ ] You have noted which actions need `class` and `version_constraint: ~1`

**If any checkbox above is unchecked, go back to Step 1.** Do not write YAML
with placeholder values intending to "fill them in later" — that never happens.

---

### Step 3 — Author the YAML

Write the YAML using the real action IDs and trigger type you collected in
Steps 1-2. Every `id` field must contain a real 32-char hex value from the API.
For plugin `config_id` values, you should have already asked the user — use the
value they provided.

**Self-check: if you are about to write the string `PLACEHOLDER` anywhere in
a YAML file, STOP. You have skipped a required step. Go back to Step 1.**

#### Resource schema rules

Every workflow YAML must include IaC metadata fields at the top:

```yaml
resource_id: vendor___workflow_name___purpose    # Stable IaC key — snake_case with ___ separators
name: 'Workflow Display Name'                    # Human-readable name (unique per CID)
description: Brief description of the workflow   # IaC documentation (stripped before API submission)
trigger: { ... }
```

- `resource_id` uses `snake_case` with `___` (triple underscore) separators between segments
- `resource_id` and `description` are stripped before API submission by `resource_deploy.py`
- Never change `resource_id` after deployment — it causes destroy + recreate

#### Key authoring rules

- Use the exact `id` and `name` from the action catalog
- Use `${data['param_name']}` to reference trigger inputs
- Use `${data['array_param.#']}` for the current loop item
- Use `${data['array_param.#.field']}` for object fields in arrays
- Use `${data['ActionLabel.OutputField']}` for prior action outputs
- Add `version_constraint: ~1` to all class-based actions (CreateVariable, UpdateVariable)
- Add `class: CreateVariable` / `class: UpdateVariable` to those actions

**Variable action IDs** (these are fixed across all CIDs):
- CreateVariable: `702d15788dbbffdf0b68d8e2f3599aa4`
- UpdateVariable: `6c6eab39063fa3b72d98c82af60deb8a`
- Print data: `aadbf530e35fc452a032f5f8acaaac2a`

> **References**:
> - `references/yaml-schema.md` — every YAML field and nesting level
> - `references/cel-expressions.md` — CEL syntax, functions, YAML quoting gotchas
> - `references/best-practices.md` — operational guidance

### Step 4 — Validate and save

#### Validate

Run validation to catch errors before saving.

```bash
# Full validation (pre-flight + API dry-run)
python .claude/skills/fusion-workflows/scripts/validate.py workflow.yaml

# Pre-flight only (no API call)
python .claude/skills/fusion-workflows/scripts/validate.py --preflight-only workflow.yaml

# Multiple files
python .claude/skills/fusion-workflows/scripts/validate.py *.yaml
```

Pre-flight checks:
- Required top-level keys (`name`, `trigger`)
- No remaining `PLACEHOLDER_*` markers
- Resource ID present and properly formatted

**Fix any errors before proceeding.** Common validation failures:
- Missing `version_constraint: ~1` on class-based actions
- Incorrect action ID (typo or action not available in CID)
- YAML quoting issues in CEL expressions (see `references/cel-expressions.md`)

#### Save

Save the validated workflow to the appropriate vendor directory:

```bash
# Save to the vendor-specific directory
# Example: resources/workflows/aws/aws___slack_alert___detection_notify.yaml
```

File naming convention: use the `resource_id` as the filename (with `.yaml` extension).

#### Commit

Stage and commit the new workflow:
```bash
git add resources/workflows/<vendor>/<filename>.yaml
git commit -m "feat(workflows): add <workflow-name>"
```

> **Deployment is outside this skill's scope.** After committing, deploy via:
> `python scripts/resource_deploy.py plan --resources=workflow` then
> `python scripts/resource_deploy.py apply --resources=workflow`

---

## Quick Reference: Common Gotchas

| Issue | Fix |
|-------|-----|
| `version constraint required` | Add `version_constraint: ~1` to the action |
| `name already exists` | Check `resources/workflows/` for duplicates, rename the workflow |
| `activity not found` | Verify action ID with `action_search.py --details <id>` |
| `PLACEHOLDER_*` in YAML | You should never have these — re-run `action_search.py` to get real IDs |
| CEL expression parse error | Check YAML quoting — see `references/cel-expressions.md` |
| `config_id` invalid | Plugin config IDs are CID-specific; find via Falcon console |
| Null coercion to `"0"` | Check both `!null` and `!'0'` in loop conditions |
| Import fails for plugin actions | Ensure plugin is installed in target CID's CrowdStrike Store |

---

## Script Reference

All scripts are in `.claude/skills/fusion-workflows/scripts/`.

| Script | Purpose | Key flags |
|--------|---------|-----------|
| `cs_auth.py` | Test credentials | Run directly for self-test |
| `action_search.py` | Find actions and resolve IDs | `--search`, `--details`, `--list`, `--vendors`, `--vendor`, `--use-case`, `--json` |
| `trigger_search.py` | List trigger types | `--list`, `--type`, `--json` |
| `validate.py` | Validate YAML | `--preflight-only`, multiple files |

---

## Reference Documents

| Document | Contents | When to read |
|----------|----------|-------------|
| `references/yaml-schema.md` | Every YAML field, nesting, data references, resource schema | Authoring any workflow |
| `references/cel-expressions.md` | CEL operators, functions, YAML quoting | Adding conditions or computed values |
| `references/trigger-types.md` | All trigger types with YAML examples | Choosing how workflow starts |
| `references/best-practices.md` | Operational guidance, limits, gotchas, IaC model | Before saving to production |

---

## Template Assets

| Template | Pattern | When to use |
|----------|---------|-------------|
| `templates/single-action.yaml` | Trigger → action → output | Simple one-shot automation |
| `templates/loop.yaml` | Trigger → loop(CV→action→UV) → output | Bulk operations on a list |
| `templates/conditional.yaml` | Trigger → loop → condition → branches | Conditional processing with skip/proceed |
| `templates/loop-conditional.yaml` | Trigger → loop → conditions → type-specific actions | Multi-type routing (e.g., IOC types) |
