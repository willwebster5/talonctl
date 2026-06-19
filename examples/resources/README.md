# Resource Format Examples

One example of each resource type managed by the talonctl IaC engine.

| File | Resource Type | Description |
|------|--------------|-------------|
| `detection.yaml` | Detection | TOR traffic correlation rule (real, deployable) |
| `saved_search_function.yaml` | Saved Search | 90-day baseline builder function (real, deployable) |
| `saved_search_hunting.yaml` | Saved Search | Certutil LOLBIN hunting query (real, deployable) |
| `lookup_file.yaml` | Lookup File | Tor exit node IP list metadata (needs CSV data) |
| `workflow.yaml` | Workflow | Notification workflow (synthetic — shows format) _(temporarily deprecated — see issue #23)_ |
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

## The `metadata:` namespace

Every resource type (detection, saved_search, dashboard, workflow, lookup_file,
rtr_script, rtr_put_file) supports an optional top-level `metadata:` block that
is **always stripped from the API payload and content hash**. Editing anything
under `metadata:` produces zero output in `talonctl plan`.

Two sub-namespaces are validated out-of-the-box:

- **`metadata.maturity:`** (universal) — track created date, last tuned date,
  tune count, and confidence level. Optional fields:
  - `created`: ISO date `YYYY-MM-DD`
  - `last_tuned`: ISO date `YYYY-MM-DD` or `null` (never tuned)
  - `tune_count`: non-negative integer
  - `confidence`: one of `low`, `medium`, `high`, `validated`

- **`metadata.ads:`** (detection-only) — Palantir Alerting & Detection Strategy
  documentation. Schema: see `examples/resources/detection.yaml` for the
  annotated reference.

Third-party frameworks may add their own sub-namespaces under `metadata.`:

```yaml
metadata:
  maturity:
    created: "2026-04-16"
  my_framework:
    anything: true
    custom_refs: ["path/to/file.md#anchor"]
```

Talonctl does not validate third-party sub-namespaces — users supply their own
validators if needed. The guarantee talonctl makes is that `metadata.<anything>`
never leaks to the API and never affects the content hash.

See the main README and CLAUDE.md for full documentation.
