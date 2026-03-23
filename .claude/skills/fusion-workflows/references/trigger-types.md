# Fusion Workflow Trigger Types

All trigger types available for CrowdStrike Fusion SOAR workflows.
Sourced from the CrowdStrike API Reference PDF and web docs.

---

## On demand

Manually executed via the Falcon console or the Execute API endpoint.
Accepts user-defined input parameters via JSON Schema.

**FQL trigger.type value**: `On demand`

```yaml
trigger:
    next:
        - FirstAction
    name: On demand
    parameters:
        $schema: https://json-schema.org/draft-07/schema
        properties:
            device_id:
                type: string
                title: Device ID
                description: The CrowdStrike device/host ID.
        required:
            - device_id
        type: object
    type: On demand
```

This is the most common trigger type. It's used for automation that's called
programmatically or from the Falcon UI.

### Parameter schema features

- Uses JSON Schema draft-07
- Supports `string`, `integer`, `boolean`, `array`, `object` types
- Arrays use `items` (can be simple types or nested objects)
- Objects use nested `properties`
- `enum` creates a dropdown in the Falcon UI
- `minItems` enforces minimum array length
- `title` and `description` appear as labels/help text in the UI
- `format` can hint at input formatting (e.g., `yyyy-MM-dd'T'HH:mm:ssZ`)
- `default` sets a default value

---

## Event (Signal)

Fires automatically when a CrowdStrike event occurs. Different event types provide
different trigger data payloads.

**FQL trigger.type value**: `Signal`

### Detection (EPP)

```yaml
trigger:
    event: Investigatable/EPP
    next:
        - FirstAction
```

Available fields: `${Trigger.Category.Investigatable.Product.EPP.Sensor.SensorID}`,
`${Trigger.Category.Investigatable.Product.EPP.Sensor.Hostname}`,
`${Trigger.Category.Investigatable.Product.EPP.URL}`

### Incident

```yaml
trigger:
    event: Incident
    next:
        - FirstAction
```

Available fields: `${Trigger.Category.Incident.Sensor.SensorID}`,
`${Trigger.Category.Incident.Sensor.Hostname}`,
`${Trigger.Category.Incident.Name}`

### Zero Trust score change

```yaml
trigger:
    event: ZeroTrust/HostScoreChange/HostOverallScoreChange
    next:
        - FirstAction
```

Available field: `${Trigger.Category.ZeroTrust.EventType.HostScoreChange.OverallScore}`

### Audit event

Fires when a user performs actions in the Falcon console (incident updates,
detection changes, policy modifications).

```yaml
trigger:
    event: Audit
    next:
        - FirstAction
```

---

## Scheduled

Runs on a cron-like schedule.

**FQL trigger.type value**: `Scheduled`

```yaml
trigger:
    next:
        - FirstAction
    name: Scheduled
    type: Scheduled
    schedule:
        cron: "0 */6 * * *"    # Every 6 hours
        timezone: UTC
```

**Warning**: Disable scheduled workflows after testing to avoid rate limiting.

---

## API

Triggered exclusively via the CrowdStrike Workflow Execution API.
Similar to On demand but not visible in the Falcon console trigger dropdown.

```yaml
trigger:
    next:
        - FirstAction
    name: API
    parameters:
        $schema: https://json-schema.org/draft-07/schema
        properties:
            input_data:
                type: string
        required:
            - input_data
        type: object
    type: API
```

---

## Workflow execution (chaining)

Fires when triggered by another workflow. Used to build modular, composable automations.

```yaml
trigger:
    next:
        - FirstAction
    name: Workflow execution
    type: Workflow execution
```

The parent workflow calls this child using an "Execute workflow" action,
passing parameters that become available as trigger data.

---

## Execution notes

- **On demand** workflows can be executed via:
  - Falcon console → Workflow → Run
  - `POST /workflows/entities/execute/v1` with `definition_id` or `name`
  - Another workflow's "Execute workflow" action

- **Event triggers** fire automatically — no manual execution needed.
  They cannot be tested with the execute endpoint; use mock executions instead.

- **Deduplication**: The `key` parameter on the execute endpoint prevents
  duplicate executions. If omitted, every call gets a unique UUID.

- **`${Workflow.Execution.Time}`** is available in all trigger types.
