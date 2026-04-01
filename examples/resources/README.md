# Resource Format Examples

One example of each resource type managed by the talonctl IaC engine.

| File | Resource Type | Description |
|------|--------------|-------------|
| `detection.yaml` | Detection | TOR traffic correlation rule (real, deployable) |
| `saved_search_function.yaml` | Saved Search | 90-day baseline builder function (real, deployable) |
| `saved_search_hunting.yaml` | Saved Search | Certutil LOLBIN hunting query (real, deployable) |
| `lookup_file.yaml` | Lookup File | Tor exit node IP list metadata (needs CSV data) |
| `workflow.yaml` | Workflow | Notification workflow (synthetic — shows format) |
| `rtr_script.yaml` | RTR Script | Windows service lister (needs PowerShell file) |
| `rtr_put_file.yaml` | RTR Put File | Config file push (synthetic — shows format) |

## Using These Examples

To deploy an example, copy it to the appropriate `resources/` subdirectory:

```bash
cp examples/resources/detection.yaml resources/detections/generic/
python scripts/resource_deploy.py plan --resources=detection
```

## Key Concepts

- **`resource_id`** — stable identifier, never change after deployment
- **`name`** — display name in Falcon console, can be updated freely
- **`_search_domain`** — which NGSIEM search domain the resource belongs to

See the main README and CLAUDE.md for full documentation.
