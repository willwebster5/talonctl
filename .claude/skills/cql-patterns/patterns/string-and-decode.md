# String and Decode Patterns

Patterns for extracting, parsing, and decoding data from event fields. Reach for these when
the data you need is buried inside a larger string — command lines, XML blobs, bitmasks,
key-value pairs, or encoded payloads.

## Pattern: regex Named Captures

**When to use:** Extract structured data from unstructured string fields (command lines, paths, connection strings)
**Complexity:** Simple
**Log sources:** Any
**Requires:** None

### Template
```cql
#event_simpleName=YourEventType

// Named capture group: (?<fieldName>pattern)
| FieldToSearch=/(?<extracted_field>REGEX_PATTERN)/i

// Multiple captures from one field
| FieldToSearch=/(?<part1>\d+\.\d+\.\d+\.\d+)\s+(?<part2>\d+)/

// Non-capturing groups for structure without creating fields: (?:...)
| case {
    field.name=/(?<classification>CONFIDENTIAL|RESTRICTED|PROPRIETARY)/i;
    field.ext=/(?:sql|db|mdb|sqlite|bak)$/i;
}
```

### Real Example
```cql
// Source: Query-Hub — Detect_Critical_Environment_Variable_Changes_over_SSH_with_Connection_Details.yml
// Extract SSH connection details (local/remote IP and port) from environment variable values

#event_simpleName=CriticalEnvironmentVariableChanged
| EnvironmentVariableName=/(SSH_CONNECTION|USER)/
| EnvironmentVariableValue=/(?<localIP>\d+\.\d+\.\d+\.\d+)\s+(?<localPort>\d+)\s+(?<remoteIP>\d+\.\d+\.\d+\.\d+)\s+(?<remotePort>\d+)$/i
| table([@timestamp, aid, userName, remoteIP, remotePort, localIP, localPort])
```

### Real Example (Categorization)
```cql
// Source: query-patterns.md — Named Capture Groups for Data Extraction
// Extract confidentiality classification from filenames

| file.extension := lower(file.extension)
| case {
    file.name=/(?<file.confidentiality>CONFIDENTIAL|RESTRICTED|PROPRIETARY|SECRET)/i;
    file.extension=/(?:sql|db|dbf|mdb|accdb|sqlite|bak|backup)$/i;
    file.extension=/(?:py|js|sh|bat|ps1|rb|go|java)$/i;
}
| groupBy(user.email, limit=max,
    function=[count(file.name, distinct=True, as=_distinct_files),
              count(file.extension, distinct=True, as=_distinct_extensions),
              collect([file.extension, file.confidentiality])])
| _distinct_files > 10 _distinct_extensions > 2
```

### Pitfalls
- Named captures create NEW fields on the event — the field name goes inside `<>` angles
- Use `strict=false` on `regex()` function calls if not all events will match (default drops non-matches)
- Non-capturing groups `(?:...)` group without creating a field — use for OR patterns in filters
- Regex runs per-event; on high-volume queries, filter first and regex second for performance
- Named capture field names can include dots (e.g., `file.confidentiality`) for nested-style naming

---

## Pattern: base64Decode()

**When to use:** Decode Base64-encoded command lines or payloads (common in PowerShell obfuscation)
**Complexity:** Medium
**Log sources:** Endpoint
**Requires:** None

### Template
```cql
#event_simpleName=ProcessRollup2
// Match encoded command flag
| CommandLine=/\-(e|enc|encodedcommand)\s+/i

// Extract the Base64 string after the flag
| EncodedString := splitString(field=CommandLine, by="-e* ", index=1)

// Decode (PowerShell uses UTF-16LE encoding)
| DecodedString := base64Decode(EncodedString, charset="UTF-16LE")

// Optional: check for nested encoding
| case {
    DecodedString=/encoded/i
    | SubEncoded := splitString(field=DecodedString, by="-EncodedCommand ", index=1)
    | SubDecoded := base64Decode(SubEncoded, charset="UTF-16LE");
    *
}
```

### Real Example
```cql
// Source: Query-Hub — Detect_and_Decode_Base64-Encoded_PowerShell_Commands.yml
// Decode Base64 PowerShell commands and check for nested encoding

#event_simpleName=ProcessRollup2 event_platform=Win ImageFileName=/.*\\powershell\.exe/
| CommandLine=/\s+\-(e|encoded|encodedcommand|enc)\s+/i
| CommandLine=/\-(?<psEncFlag>(e|encoded|encodedcommand|enc))\s+/i
| length("CommandLine", as="cmdLength")
| groupby([psEncFlag, cmdLength, CommandLine],
    function=stats([count(aid, distinct=true, as="uniqueEndpointCount"),
                    count(aid, as="executionCount")]), limit=max)
| EncodedString := splitString(field=CommandLine, by="-e* ", index=1)
| CmdLinePrefix := splitString(field=CommandLine, by="-e* ", index=0)
| DecodedString := base64Decode(EncodedString, charset="UTF-16LE")
| case {
    DecodedString=/encoded/i
    | SubEncodedString := splitString(field=DecodedString, by="-EncodedCommand ", index=1)
    | SubDecodedString := base64Decode(SubEncodedString, charset="UTF-16LE");
    *
}
| table([executionCount, uniqueEndpointCount, cmdLength, DecodedString, CommandLine])
| sort(executionCount, order=desc)
```

### Pitfalls
- PowerShell `-EncodedCommand` uses UTF-16LE — always specify `charset="UTF-16LE"` for PS payloads
- The `splitString` by pattern uses glob-style matching (`-e* ` matches `-enc `, `-encodedcommand `, etc.)
- Some payloads have nested encoding — always check the decoded output for further encoded content
- Invalid Base64 input returns an empty string, not an error — validate results
- `base64Decode` without charset defaults to UTF-8; wrong charset produces garbled output

---

## Pattern: parseXml()

**When to use:** Extract fields from XML content embedded in event fields (scheduled tasks, GPO, config blobs)
**Complexity:** Simple
**Log sources:** Endpoint
**Requires:** Event field containing valid XML

### Template
```cql
#event_simpleName=YourEventWithXml
// Parse the XML field — creates nested fields matching XML structure
| parseXml(XmlFieldName)

// Access parsed values using dot notation matching the XML hierarchy
| ExtractedValue := rename(Root.Element.SubElement)

// Filter on extracted values
| ExtractedValue=/pattern/i
```

### Real Example
```cql
// Source: Query-Hub — hidden_scheduled_tasks.yml
// Find scheduled tasks with the Hidden flag set to true

#event_simpleName=ScheduledTaskRegistered
| parseXml(TaskXml)
| Hidden := rename(Task.Settings.Hidden)
| Hidden=/true/i
| table([aid, Hidden, TaskXml], limit=1000)
```

### Pitfalls
- `parseXml()` creates fields matching the exact XML element hierarchy (e.g., `Task.Settings.Hidden`)
- Field names are case-sensitive and must match the XML element names exactly
- Arrays in XML (repeated elements) become multi-value fields — use `collect()` or indexing to access
- Very large XML blobs can impact performance — filter events before parsing when possible
- Not all XML is valid — malformed XML silently fails to parse

---

## Pattern: bitfield:extractFlags()

**When to use:** Decode numeric bitmask fields into named boolean flags
**Complexity:** Simple
**Log sources:** Endpoint
**Requires:** Knowledge of the bit positions for the target field

### Template
```cql
#event_simpleName=YourEventType
| bitfield:extractFlags(
    field=BitmaskField,
    output=[
        [0, FLAG_NAME_BIT_0],
        [1, FLAG_NAME_BIT_1],
        [2, FLAG_NAME_BIT_2]
        // Add bit positions as needed
    ])
// Filter to specific flag states
| FLAG_NAME_BIT_2="true"
```

### Real Example (SignInfoFlags)
```cql
// Source: Query-Hub — Decode_SignInfoFlags.yml
// Decode process signature flags to find unsigned or improperly signed executables

#event_simpleName=ProcessRollup2 UserSid=/^S-1-5-21-/ SignInfoFlags=*
| bitfield:extractFlags(
    field=SignInfoFlags,
    output=[
      [0,  SIGNATURE_FLAG_SELF_SIGNED],
      [1,  SIGNATURE_FLAG_MS_SIGNED],
      [9,  SIGNATURE_FLAG_NO_SIGNATURE],
      [10, SIGNATURE_FLAG_INVALID_SIGN_CHAIN],
      [11, SIGNATURE_FLAG_SIGN_HASH_MISMATCH],
      [18, SIGNATURE_FLAG_HAS_VALID_SIGNATURE],
      [28, SIGNATURE_FLAG_CERT_EXPIRED],
      [29, SIGNATURE_FLAG_CERT_REVOKED]
    ])
```

### Real Example (SensorStateBitMap)
```cql
// Source: Query-Hub — detect_locally_disabled_rtr.yml
// Detect hosts where RTR has been locally disabled

#event_simpleName=SensorHeartbeat
| groupBy([aid], function=selectLast([@timestamp, ComputerName, SensorStateBitMap]), limit=max)
| bitfield:extractFlags(
    field=SensorStateBitMap,
    output=[
      [2, RTR_Locally_Disabled]
    ])
| RTR_Locally_Disabled="true"
```

### Pitfalls
- Bit positions are zero-indexed — bit 0 is the least significant bit
- Output values are strings `"true"` / `"false"`, not booleans — filter with `="true"` not `=true`
- You don't need to decode ALL bits — only include the positions you care about
- Multiple flags can be true simultaneously (that's the point of bitmasks)
- CrowdStrike documents bit positions in the Event Dictionary — check there for field-specific mappings

---

## Pattern: kvParse()

**When to use:** Parse key=value formatted strings into individual fields
**Complexity:** Simple
**Log sources:** Any
**Requires:** Events with key=value formatted content

### Template
```cql
// Option A: Parse a field containing key=value pairs
| kvParse(field=YourField)

// Option B: Parse from createEvents (for building lookup tables)
createEvents(["key1=value1 key2=value2", "key1=value3 key2=value4"])
| kvParse()
```

### Real Example
```cql
// Source: Query-Hub — assigned_sensor_update_policy.yml
// Build a release type lookup table from key=value event strings

defineTable(query={
    createEvents([
        "release_id=tagged|1 release.type=N-1",
        "release_id=tagged|2 release.type=N-2",
        "release_id=tagged|11 release.type=\"Auto Latest\"",
        "release_id=tagged|16 release.type=\"Auto EA\""
    ])
    | kvParse()
}, include=[release_id, release.type], name="release_type_lookup")
```

### Pitfalls
- `kvParse()` expects `key=value` format separated by spaces; quoted values handle spaces within values
- Field names with dots (e.g., `release.type`) are valid but may need quoting in subsequent references
- Duplicate keys overwrite — the last value wins
- `kvParse()` without a field argument parses the raw event string; specify `field=` for targeted parsing
- Values with special characters may need quoting in the source data

---

## Pattern: splitString()

**When to use:** Split a field on a delimiter and extract a specific segment by index
**Complexity:** Simple
**Log sources:** Any
**Requires:** None

### Template
```cql
// Split field on delimiter and take a specific index (0-based)
| part := splitString(field=SourceField, by="delimiter", index=0)

// Common use: extract before/after a separator
| prefix := splitString(field=FullString, by="separator", index=0)
| suffix := splitString(field=FullString, by="separator", index=1)
```

### Real Example
```cql
// Source: Query-Hub — Detect_and_Decode_Base64-Encoded_PowerShell_Commands.yml
// Split command line on the encoded flag to separate prefix from payload

#event_simpleName=ProcessRollup2 event_platform=Win ImageFileName=/.*\\powershell\.exe/
| CommandLine=/\s+\-(e|encoded|encodedcommand|enc)\s+/i
| EncodedString := splitString(field=CommandLine, by="-e* ", index=1)
| CmdLinePrefix := splitString(field=CommandLine, by="-e* ", index=0)
| DecodedString := base64Decode(EncodedString, charset="UTF-16LE")
```

### Pitfalls
- `index` is zero-based — `index=0` is the part before the first delimiter occurrence
- The `by` parameter supports glob patterns (`-e* ` matches `-enc `, `-encodedcommand `, etc.)
- If the delimiter is not found, `index=0` returns the entire string; higher indexes return null
- For multiple delimiters, chain `splitString` calls or use `regex()` with named captures instead
- No negative indexing — you cannot split from the end without knowing the total number of segments
