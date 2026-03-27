# SOC Skill v3 — Agent-Delegated Phase Architecture

## Overview

v3 builds on the v2 decomposed-phase architecture by adding capability-based agent delegation. The Opus orchestrator dispatches bounded tasks to cheaper/faster models (Sonnet for substantive work, Haiku for mechanical tasks) while retaining judgment, classification, and write operations.

**Full design spec:** `docs/superpowers/specs/2026-03-22-soc-v3-agent-delegation-design.md` (in command-center repo)

## Architecture

```
User <-> Opus Orchestrator (v3 phase dispatcher with delegation)
              |
              +-- Phase 1 (Intake) → alert-formatter-agent (Haiku, silent)
              +-- Phase 2 (Triage) → cql-query + mcp-investigator + evidence-summarizer (Sonnet, visible)
              +-- Phase 3 (Classify) → NO DELEGATION (Opus judgment)
              +-- Phase 4 (Close) → NO DELEGATION (write operations)
              +-- Phase 5 (Tune) → cql-query + syntax-validator (Sonnet/Haiku)
              +-- Hunt Mode → cql-query + mcp-investigator + evidence-summarizer
              +-- Investigate Mode → cql-query + mcp-investigator
              +-- Daily Mode → alert-formatter + per-alert agents based on tier
```

## What Changed from v2

| Aspect | v2 | v3 |
|--------|----|----|
| Phase structure | 5 phases + 3 modes | Same — unchanged |
| Human checkpoints | 4 blocking checkpoints | Same — unchanged |
| Memory loading | Staged by phase | Same — unchanged |
| MCP tool calls | All by orchestrator (Opus) | Read-only delegated to agents; write stays with orchestrator |
| CQL query writing | Orchestrator (Opus) | cql-query agent (Sonnet) |
| Evidence collection | Orchestrator (Opus) | mcp-investigator agent (Sonnet) |
| Evidence summary | Orchestrator (Opus) | evidence-summarizer agent (Sonnet) |
| Alert formatting | Orchestrator (Opus) | alert-formatter agent (Haiku) |
| CQL validation | Orchestrator (Opus) | syntax-validator agent (Haiku) |

## What Did NOT Change

- Phase routing logic, human checkpoint structure, memory file loading protocol
- Living documents update protocol, eval mode behavior, playbook loading
- Phase 3 (Classify) and Phase 4 (Close) — no delegation, Opus-only
- All write operations require human approval

## v2 RED Phase Issues (Still Addressed)

All three v2 fixes carry forward unchanged:
1. **Confirmation bias**: FP patterns still load at Phase 3 only (after evidence collection)
2. **Data source discovery**: `investigation-techniques.md` repo mapping still loaded at Phase 2; now provided to cql-query agent
3. **Stale memory**: Phase 5 still requires deployed state verification before tuning

## Agents

See `agents/` directory for prompt files. Each agent has: Role, Input Protocol, Output Contract, Guardrails, Examples.
