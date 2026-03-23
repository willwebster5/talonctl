# SOC Skill v2 — Decomposed Phase Architecture

## Problem Statement

SOC v1 loads all context (environmental + memory + FP patterns) at session start before any alerts are fetched. This causes:

1. **Confirmation bias** — partial pattern matches in memory cause premature classification without investigation
2. **Investigation shortcuts** — agent skips enrichment queries because memory provides a "good enough" answer
3. **No human checkpoints** — monolithic skill runs from intake to close with no structured pause points

### RED Phase Evidence (2026-03-20 triage session)

| Failure | Root Cause | What v2 Must Fix |
|---------|-----------|-------------------|
| User alert attributed to iCloud Private Relay without checking IP | MEMORY.md loaded before investigation; "user + iPhone" partial-matched to known Private Relay FP pattern | FP patterns must not load until AFTER investigation evidence is collected |
| Queried `microsoft_graphapi` repo 3x (empty) instead of `fcs_csp_events` | Investigation technique gap — no repo mapping for EntraID sign-in logs | Investigation techniques file must include data source → repo mappings |
| Diagnosed GitHub direct push detection as needing tuning | Memory entry said "detection needs tuning" (stale); didn't verify deployed query first | Classification must verify current state before applying memory patterns |

## Architecture: Phased Skill Invocation

### Phase 1: Intake (`/soc intake` or `/soc daily`)

**Context loaded:**
- `environmental-context.md` — static org knowledge (accounts, users, infrastructure)
- `memory/fast-track-patterns.md` — high-confidence bulk-close patterns only (CWPP, Charlotte AI, HR platform provisioning)

**NOT loaded:**
- FP/TP pattern memory
- Tuning history
- Investigation techniques (loaded on demand per alert type)

**Actions:**
- Fetch alerts by product
- Assign triage depth tiers (fast-track, pattern-match candidate, standard, deep)
- Present summary table
- **STOP — human reviews tiers, selects alerts to investigate**

**Fast-track tier:** Can be closed directly from intake using fast-track patterns only.

### Phase 2: Triage (`/soc triage <alert-id>`)

**Context loaded (additive):**
- `memory/investigation-techniques.md` — query patterns, field gotchas, data source mappings
- Relevant playbook based on alert type routing

**NOT loaded:**
- FP/TP pattern memory (prevents confirmation bias)
- Tuning history

**Actions:**
- Call `alert_analysis` for enrichment
- Run follow-up queries (EDR, CloudTrail, cloud assets, EntraID)
- Collect evidence: who, what, when, where, how
- Present evidence summary with key IOCs
- **STOP — human reviews evidence before classification**

**Critical rule:** Agent must form evidence-based assessment BEFORE any memory patterns are consulted.

### Phase 3: Classify (`/soc classify <alert-id>`)

**Context loaded (additive):**
- `memory/fp-patterns.md` — known FP signatures with IOC details
- `memory/tp-patterns.md` — known TP indicators

**Actions:**
- Compare collected evidence against memory patterns
- If match found: cite specific pattern AND verify evidence supports it (not just partial match)
- If no match: classify from evidence alone
- Run classification checkpoint (4 questions from v1)
- Present triage summary with classification + reasoning
- **STOP — human approves classification**

**Critical rule:** Memory patterns are VALIDATION, not shortcuts. A partial match (e.g., "same user seen before") is insufficient — evidence must independently support the classification.

### Phase 4: Close (`/soc close <alert-id> <classification>`)

**Actions:**
- Execute `update_alert_status` with approved classification
- Add comments and tags
- If TP: case creation workflow (P0/P1 always, P2 if multi-system)
- Update `memory/fp-patterns.md` or `memory/tp-patterns.md` with new patterns

### Phase 5: Tune (`/soc tune <detection>`)

**Context loaded:**
- `memory/tuning-log.md` — past tuning decisions
- `tuning-bridge.md` — IOC → tuning pattern mapping
- Detection tuning skill context (AVAILABLE_FUNCTIONS.md, TUNING_PATTERNS.md)

**Actions:**
- Find detection template
- Load tuning context (hard stop — same as v1)
- **Verify currently deployed query matches template** (new requirement from RED phase)
- Propose tuning with diff
- **STOP — human approves before edit**
- Apply, validate CQL, update alert

## Memory File Split

Current `MEMORY.md` splits into:

| File | Contents | Loaded When |
|------|----------|-------------|
| `memory/fast-track-patterns.md` | CWPP noise, Charlotte AI signals, HR platform provisioning, Intune compliance drift | Phase 1 (intake) |
| `memory/fp-patterns.md` | All known FP patterns with IOC signatures | Phase 3 (classify) |
| `memory/tp-patterns.md` | Known TP indicators | Phase 3 (classify) |
| `memory/tuning-log.md` | Tuning decisions with dates + rationale | Phase 5 (tune) |
| `memory/investigation-techniques.md` | Query patterns, field gotchas, repo mappings, API quirks | Phase 2 (triage) |
| `memory/detection-ideas.md` | Future detection concepts (moved from DETECTION_IDEAS.md) | On demand |
| `memory/tuning-backlog.md` | Pending tuning work (moved from TUNING_BACKLOG.md) | Phase 5 (tune) |

## Eval Scenarios

### Scenario 1: Confirmation Bias Resistance

**Setup:** Alert for a user previously seen in a known FP pattern, but from a DIFFERENT source IP/ASN than the known pattern.

**v1 expected behavior (RED):** Classifies as FP citing known pattern without verifying IP differs from documented pattern.

**v2 expected behavior (GREEN):** Investigates IP independently in Phase 2, discovers it doesn't match known pattern, presents evidence in Phase 2 output. Only loads FP patterns in Phase 3, notes partial match but flags IP discrepancy.

### Scenario 2: Data Source Discovery

**Setup:** Alert type that requires querying a non-obvious NGSIEM repo (e.g., EntraID sign-in logs in `fcs_csp_events`, not `microsoft_graphapi`).

**v1 expected behavior (RED):** Queries wrong repo, gets 0 results, tries variations, eventually needs human correction.

**v2 expected behavior (GREEN):** `investigation-techniques.md` includes explicit repo mapping table. Phase 2 loads this before running queries.

### Scenario 3: Stale Memory vs Current State

**Setup:** Alert where memory says "detection needs tuning" but the detection has since been fixed/deployed.

**v1 expected behavior (RED):** Proposes tuning based on memory without verifying deployed state.

**v2 expected behavior (GREEN):** Phase 2 queries current detection behavior. Phase 3 loads memory, finds stale entry, flags discrepancy. Recommends updating memory, not tuning detection.

### Scenario 4: Fast-Track Efficiency (Regression Test)

**Setup:** Batch of CWPP informational alerts + HR platform provisioning alerts.

**v1 expected behavior:** Bulk closes efficiently.

**v2 expected behavior (must match):** Same efficiency — fast-track patterns loaded at intake, no regression.

## Implementation Plan

1. Split `MEMORY.md` into memory files per table above
2. Rewrite `SKILL.md` as phase dispatcher (routes to sub-phases)
3. Create phase-specific skill files or sections
4. Add repo mapping table to `investigation-techniques.md`
5. Add "verify deployed state" requirement to classify and tune phases
6. Run eval scenarios with `--eval` flag comparing v1 vs v2
7. Iterate on loopholes discovered during eval

## Implementation Status

| Step | Status | Notes |
|------|--------|-------|
| Split MEMORY.md into memory files | Done | 7 files in `memory/` — fast-track, fp, tp, investigation-techniques, tuning-log, tuning-backlog, detection-ideas |
| Rewrite SKILL.md as phase dispatcher | Done | 5 phases + daily/hunt/investigate modes, all v1 capabilities preserved |
| Add repo mapping to investigation-techniques.md | Done | 8 platforms mapped, field gotchas table added |
| Add "verify deployed state" to Phase 5 | Done | Step 2 in Phase 5 — required before proposing tuning |
| Run eval scenarios v1 vs v2 | Pending | Next: live triage comparison |
| Iterate on loopholes | Pending | After eval run |

## Resolved Questions

- **Phases as separate files or sections?** → Sections within one SKILL.md. Keeps the skill self-contained; phases are conceptual boundaries enforced by context loading rules, not file boundaries.
- **Daily mode with 16 alerts?** → Batch orchestrator section in SKILL.md. Fast-tracks close in Phase 1, pattern-match candidates get brief Phase 2+3, standard/deep get full treatment. Human selects order.
- **Human checkpoint optional?** → No. Evidence review before classification is the core anti-confirmation-bias mechanism. Non-negotiable.
- **Cross-alert correlation?** → Handled in daily mode Phase 1 (summary table shows all alerts). Individual phases process one at a time but analyst sees the full picture from the summary.
