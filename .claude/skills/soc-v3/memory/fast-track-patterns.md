<!-- PHASE: Intake (Phase 1)
     LOADED BY: /soc daily, /soc intake
     PURPOSE: High-confidence patterns for bulk close without investigation.
     UPDATE: Add patterns here ONLY when they meet ALL criteria:
       1. 100% confidence — no investigation needed
       2. Recurring noise — appears multiple times per week
       3. Never been a TP — historical pattern is always benign -->

# Fast-Track Patterns

Patterns in this file can be bulk-closed at intake without investigation. They are loaded at Phase 1 before alerts are fetched.

## Format

Each pattern should include:
- **Prefix**: Alert composite ID prefix (e.g., `cwpp:`, `thirdparty:`, `ind:`)
- **Patterns**: Specific detection names or identifiers
- **Severity**: Expected severity level
- **Volume**: Approximate daily/weekly volume
- **Action**: How to close (tag, comment)
- **Rule**: Machine-readable matching criteria
- **Tunability**: Whether the alert can be tuned in NGSIEM

<!-- Add your fast-track patterns here. Examples: CWPP container image noise, automated lead signals, compliance drift alerts, VPN reconnect alerts. -->
