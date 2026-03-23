# Fusion Workflow YAML Schema Reference

Complete field reference for CrowdStrike Fusion SOAR workflow YAML files,
adapted for our IaC resource schema.

---

## Resource Schema Wrapper (IaC Fields)

Our workflows use a resource schema that wraps the native Fusion YAML with IaC metadata fields:

```yaml
resource_id: vendor___workflow_name___purpose    # REQUIRED. Stable IaC key — snake_case with ___ separators. NEVER change after deployment.
name: 'Workflow Display Name'                    # Human-readable display name in Falcon console
description: Brief description of what this workflow does  # IaC documentation field
trigger: { ... }                                 # Native Fusion fields below
actions: { ... }
loops: { ... }
output_fields: []
```

### IaC field rules

- **`resource_id`** (required): Stable identifier used as the state key. Uses `snake_case` with triple-underscore (`___`) separators between logical segments (e.g., `aws___slack_alert___detection_notify`). Never change after deployment — changing it causes destroy + recreate.
- **`description`**: Human-readable documentation for the workflow. Used in IaC context only.
- **Both `resource_id` and `description` are stripped before API submission.** The deployment script (`resource_deploy.py`) removes these fields before sending the YAML to the CrowdStrike import endpoint.
- **Deployment is via `resource_deploy.py plan/apply`**, not via this skill. This skill authors and validates YAML only.

---

## Top-Level Structure

```yaml
name: '<string>'                    # Unique per CID. Use quotes if it contains brackets.
description: <string>               # IaC documentation (stripped before API submission)
trigger: { ... }                    # Required. How the workflow starts.
actions: { ... }                    # Top-level actions (outside loops)
loops: { ... }                      # Loop definitions
output_fields: []                   # Fields surfaced to the caller
```

---

## trigger

```yaml
trigger:
    next:                           # First node(s) to execute
        - ActionLabel               # Reference to an action, loop, or condition
    name: On demand                 # Display name
    type: On demand                 # Trigger type (see trigger-types.md)
    parameters:                     # Input schema (On demand / API triggers)
        $schema: https://json-schema.org/draft-07/schema
        properties:
            my_param:
                type: string        # string | integer | boolean | array | object
                title: My Param     # Display label in Falcon UI
                description: ...    # Help text
        required:
            - my_param
        type: object
```

**Parameter types**: `string`, `integer`, `boolean`, `array` (with `items`), `object` (with nested `properties`).
Arrays can have `minItems`. Strings can have `enum` for dropdown values.

---

## actions

Each action is a named node with a unique label (PascalCase recommended).

```yaml
actions:
    ContainDevice:                  # Node label — referenced by next/conditions
        id: bec9fbeb...            # 32-char hex from the action catalog (global, not per-CID)
        name: Contain device        # Display name (must match catalog name)
        next:                       # Next node(s) to execute
            - UpdateVariable
        properties:                 # Action-specific inputs
            device_id: ${data['device_id']}
            note: ${data['note']}
```

### Class-based actions (CreateVariable, UpdateVariable)

These require `class` and `version_constraint`:

```yaml
CreateVariable:
    id: 702d15788dbbffdf0b68d8e2f3599aa4    # Fixed ID for CreateVariable
    class: CreateVariable
    name: Create variable
    next:
        - NextAction
    properties:
        variable_schema:
            properties:
                my_field:
                    type: string
                my_flag:
                    type: boolean
            required:
                - my_field
            type: object
    version_constraint: ~1          # REQUIRED for class-based actions
```

```yaml
UpdateVariable:
    id: 6c6eab39063fa3b72d98c82af60deb8a    # Fixed ID for UpdateVariable
    class: UpdateVariable
    name: Update variable
    properties:
        WorkflowCustomVariable:     # Always this key
            my_field: ${data['some.path']}
            my_flag: true
    version_constraint: ~1
```

**Well-known fixed IDs**:
- CreateVariable: `702d15788dbbffdf0b68d8e2f3599aa4`
- UpdateVariable: `6c6eab39063fa3b72d98c82af60deb8a`
- Print data: `aadbf530e35fc452a032f5f8acaaac2a`

### Third-party / plugin actions

Actions from CrowdStrike Store plugins (Okta, Entra ID, Mimecast, etc.) use `config_id` and `params`:

```yaml
OktaRevokeSessions:
    id: 5092e629ba5f421abc057b72ea123c59
    name: Okta - Revoke Sessions
    properties:
        config_id: bb72f1a93d89473b8c0bd1a3317fb1a9  # Plugin instance ID (per-CID)
        params:
            path:
                Okta User ID: ${data['GetUserIdentityContext.UserOktaObjectID']}
            query:
                oauthTokens: true
```

**Warning**: `config_id` values are CID-specific. Workflows using them cannot be imported into a different CID without updating these IDs.

---

## loops

```yaml
loops:
    Loop:
        display: For each Device IDs; Sequentially
        name: For each Device IDs; Sequentially
        for:
            input: device_ids       # Parameter name containing the array
            continue_on_partial_execution: false
            sequential: true        # true = one at a time; false = parallel
        trigger:
            next:
                - CreateVariable    # First node inside the loop
        actions:
            CreateVariable: { ... }
            SomeAction: { ... }
            UpdateVariable: { ... }
        conditions:                 # Optional conditions inside the loop
            my_condition: { ... }
        output_fields:              # Fields collected per iteration
            - WorkflowCustomVariable.field_name
```

**Loop limits**: 100,000 iterations max. 7-day max execution window.

### Nested loops

Loops can contain sub-loops under their `actions` key using a `loops` sub-key:

```yaml
actions:
    SomeAction:
        ...
        loops:
            InnerLoop:
                for:
                    input: SomeAction.results
                ...
```

---

## conditions

Two expression syntaxes are available. Use the appropriate YAML key:

### CEL expressions (`cel_expression`)

For data comparisons, type checks, string matching:

```yaml
conditions:
    is_ip:
        next:
            - ProcessIP
        cel_expression: data['iocs.#.ioc_type'] == 'ip'
        display:
            - IOC type is IP
```

### FQL-style expressions (`expression`)

For membership/inclusion checks (e.g., group membership):

```yaml
conditions:
    not_in_skip_group:
        next:
            - ProcessUser
        expression: GetUserIdentityContext.Groups:!['SkipCrowdStrikeWorkflows']
        display:
            - User groups does not include SkipCrowdStrikeWorkflows
        else:
            - SkipAction
```

**`else` branch**: Only supported with `expression`, not `cel_expression`.
With `cel_expression`, mutually exclusive conditions must be separate nodes.

---

## Data references (`${data['...']}`)

### Trigger parameters
- `${data['param_name']}` — top-level trigger input
- `${data['param.nested_field']}` — nested object field

### Loop iteration
- `${data['array_param.#']}` — current item (simple array)
- `${data['array_param.#.field']}` — field of current object item

### Action output
- `${data['ActionLabel.FieldName']}` — output from a prior action
- `${data['ActionLabel.Nested.Path']}` — nested output field

### Custom variable
- `${data['WorkflowCustomVariable.field']}` — read current custom variable value

### Event trigger variables
- `${Trigger.Category.Investigatable.Product.EPP.Sensor.SensorID}`
- `${Trigger.Category.Incident.Name}`
- `${Workflow.Execution.Time}`

---

## output_fields

Declares which fields are returned to the caller.

```yaml
# Inside a loop — collect per-iteration results
output_fields:
    - WorkflowCustomVariable.device_id
    - WorkflowCustomVariable.contained

# Top level — surface loop output
output_fields:
    - Loop.output
```

For non-loop workflows, output fields reference action results directly:
```yaml
output_fields:
    - ActionLabel.FieldName
```

---

## version_constraint

Required for class-based actions (CreateVariable, UpdateVariable) and some catalog actions.
Always use `~1` (semver compatible with major version 1).

```yaml
version_constraint: ~1
```

Omitting this on actions that require it causes import validation failures.

---

## Script Reference

All scripts for this skill are in `.claude/skills/fusion-workflows/scripts/`:

| Script | Purpose |
|--------|---------|
| `action_search.py` | Discover actions and resolve 32-char hex IDs |
| `trigger_search.py` | List trigger types and YAML structures |
| `validate.py` | Pre-flight + API dry-run validation |
| `cs_auth.py` | Test CrowdStrike API credentials |
