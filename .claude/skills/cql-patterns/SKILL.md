---
name: cql-patterns
description: CQL pattern catalog — curated detection engineering patterns for CrowdStrike NG-SIEM. Use when writing, reviewing, or debugging CQL queries.
allowed-tools: Read, Grep, Glob
---

# CQL Pattern Catalog

Curated, battle-tested CQL patterns for detection engineering in CrowdStrike NG-SIEM. This is a pattern catalog, not an API reference — it shows *how* to combine CQL functions into effective detections. For function-level documentation, see `crowdstrike-resources/docs/CQL/`.

## Pattern Categories

| Category | File | When to Use |
|----------|------|-------------|
| Correlation | `patterns/correlation.md` | Multi-event detection: defineTable chains, correlate() sequences, readFile merge |
| Enrichment | `patterns/enrichment.md` | Adding context: join, selfJoinFilter, match() with CSV lookups, ipLocation, aid_master |
| Aggregation | `patterns/aggregation.md` | Summarizing events: groupBy with thresholds, bucket() time windows, timeChart, session() |
| String & Decode | `patterns/string-and-decode.md` | Parsing data: regex named captures, base64Decode, parseXml, bitfield:extractFlags, kvParse |
| Scoring | `patterns/scoring.md` | Risk assessment: weighted case{} scoring, severity tiering, slidingTimeWindow+rulesHit |
| Baselining | `patterns/baselining.md` | Anomaly detection: neighbor() sequential analysis, time-window baselines, geography:distance |
| Output | `patterns/output.md` | Formatting results: table vs select, format() for deep links, unit:convert, formatTime |

## Routing Logic

Load pattern files based on your current task:

| Task | Load These |
|------|------------|
| Writing a new detection | scoring + correlation |
| Hunting / investigation | enrichment + aggregation |
| Tuning an existing detection | baselining + scoring |
| Debugging query output | output + string-and-decode |
| All tasks | Read this entry point first for global gotchas below |

## Global CQL Gotchas

Critical pitfalls that apply across all CQL work. Read these before writing any query.

1. **`#` prefix REQUIRED for tagged fields.** `#event_simpleName=DnsRequest` not `event_simpleName=DnsRequest` — unprefixed silently returns 0 results with no error.

2. **Query optimization order.** Put cheap filters first, expensive operations last:
   > time filter -> tag filter -> field filter -> negative filter -> regex -> functions -> aggregation -> rename -> join -> view

3. **`table()` vs `select()`.** `table()` creates a new result set and is an aggregation (limits to 200 rows by default). `select()` picks fields from existing results without limiting rows. Use `select()` unless you specifically need aggregation behavior.

4. **String comparison is case-sensitive by default.** Use `/pattern/i` for case-insensitive matching.

5. **`join()` default mode is `inner`.** Use `mode=left` to preserve all events from the base query when the join table has no match.

6. **IP enrichment chain order.** Run in this sequence — each adds fields the next can use:
   `ipLocation()` -> `asn()` -> `rdns()`. Run these *after* `groupBy()` so they execute once per unique IP, not once per raw event.

7. **Saved search description limit: 2000 characters.** Keep `description` brief; put full documentation in `queryString` comments.

8. **NG-SIEM query timeout: ~120 seconds.** Break complex queries into stages using `defineTable` to avoid timeouts.

9. **Pre-calculate arithmetic.** Do division/multiplication *before* case/test blocks, not inside them.

10. **Handle null baselines.** Always handle missing data with `case { field!=* | default; * }` or `default()`.

11. **Profile with `explain:asTable()`.** Append to any query to get per-stage performance metrics (timeMs, event counts, prefilter effectiveness). Use it to validate optimization order and find bottlenecks. **Ad hoc only** — do not include in scheduled searches, triggers, or dashboards. Not supported with `correlate()`. See output patterns for details.

## Raw Reference

For complete CQL function API documentation, see `crowdstrike-resources/docs/CQL/docs/CrowdStrike-Query-Language/combined.md` or individual function files in that directory.
