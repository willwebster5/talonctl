# CQL Query Patterns

## CQL Patterns — Catalog Reference

For CQL syntax patterns, use the cql-patterns skill:
- Invoke `/cql-patterns` for the full catalog
- Or read specific pattern files directly:
  - `.claude/skills/cql-patterns/patterns/correlation.md` — defineTable chains, correlate(), multi-stage joins
  - `.claude/skills/cql-patterns/patterns/enrichment.md` — join, selfJoinFilter, match() with lookups, ipLocation chain
  - `.claude/skills/cql-patterns/patterns/aggregation.md` — groupBy, bucket, timeChart, thresholds
  - `.claude/skills/cql-patterns/patterns/string-and-decode.md` — regex, base64Decode, parseXml, bitfield
  - `.claude/skills/cql-patterns/patterns/scoring.md` — weighted scoring, severity tiering, slidingTimeWindow
  - `.claude/skills/cql-patterns/patterns/baselining.md` — neighbor(), baselines, geography:distance
  - `.claude/skills/cql-patterns/patterns/output.md` — table vs select, deep links, formatting

---

## Best Practices

1. **Always include risk categorization** - Use case statements to assign severity levels
2. **Enrich with user context** - Join with user lookup files for display names
3. **Add geolocation data** - Use ipLocation() for external connections
4. **Format timestamps** - Convert to EST/local timezone for investigation
5. **Create investigation IDs** - Use format() to generate unique identifiers
6. **Provide actionable outputs** - Include specific remediation recommendations
7. **Test incrementally** - Start simple, add complexity step by step
8. **Document assumptions** - Use comments to explain exclusions and thresholds
9. **Pre-calculate arithmetic** - Do division/multiplication before case/test blocks
10. **Handle null baselines** - Always handle missing data with `case { field!=* | default; * }` or `default()`
11. **Use temporal gating** - Prevent duplicate alerts with `now()` and cutoff times
12. **Filter early** - Apply specific conditions before expensive operations (enrichment, groupBy)
