# CEL Expressions in Fusion Workflows

CrowdStrike Fusion uses Google's Common Expression Language (CEL) for conditional logic
and data transformation. This reference covers syntax, CrowdStrike-specific extensions,
and YAML quoting rules.

---

## Where CEL is used

- **`cel_expression`** key in `conditions` blocks — routing logic
- **HTTP Action bodies** — data transformation before sending to external APIs
- **Property templates** — complex computed values in `${...}` expressions

---

## Basic operators

| Operator | Description | Example |
|----------|-------------|---------|
| `==` | Equality | `data['type'] == 'ip'` |
| `!=` | Inequality | `data['status'] != 'closed'` |
| `<`, `>`, `<=`, `>=` | Comparison | `data['score'] >= 80` |
| `&&` | Logical AND | `a == 'x' && b == 'y'` |
| `\|\|` | Logical OR | `a == 'x' \|\| a == 'y'` |
| `!` | Logical NOT | `!cs.cidr.valid(data['ip'])` |
| `? :` | Ternary | `(x != null ? x : 'default')` |
| `in` | Membership | `'admin' in data['roles']` |
| `+` | String concat / list concat | `data['a'] + data['b']` |

---

## List comprehensions

```
list.map(item, expr)         # Transform: [1,2,3].map(x, x * 2) → [2,4,6]
list.filter(item, cond)      # Filter:    [1,2,3].filter(x, x > 1) → [2,3]
list.exists(item, cond)      # Any match: [1,2,3].exists(x, x > 2) → true
list.all(item, cond)         # All match: [1,2,3].all(x, x > 0) → true
list.exists_one(item, cond)  # Exactly one match
```

**Real example** (extracting host IDs from ThreatGraph results):
```
${data['GetDevicesIPv4.Connections'].map(item, item.HostID)}
```

---

## String functions

```
string.contains('sub')       # Substring check
string.startsWith('prefix')
string.endsWith('suffix')
string.matches('regex')      # RE2 regex match
size(string)                 # Length
```

---

## CrowdStrike custom CEL functions

These are extensions not in standard CEL:

### `cs.cidr.valid(string)` → bool
Check if a string is a valid IPv4/IPv6 address or CIDR.
```
cs.cidr.valid(data['iocs.#'])
```

### `cs.string.find(string, regex)` → string
Find the first regex match in a string. Returns the match or empty string.
```
cs.string.find(data['iocs.#'], '[A-Fa-f0-9]{64}') == data['iocs.#']
```
This pattern checks if the entire string is a 64-char hex (SHA256).

### `cs.map.merge(list_of_maps)` → map
Merge multiple maps into one. Later entries overwrite earlier ones.
```
cs.map.merge([
    {"searchReason": data['searchReason']},
    (data['from'] != null ? {"from": data['from']} : {})
])
```
Combined with ternary operators, this builds conditional JSON bodies.

### `has(field)` — standard CEL
Test if a field exists (not null).
```
has(data['optional_field'])
```

---

## YAML quoting rules — critical gotchas

### Single quotes in `cel_expression` values

CEL expressions use `data['field']` with single quotes. In YAML, this requires careful quoting:

**Option 1 — Unquoted (works when no YAML special chars present)**:
```yaml
cel_expression: data['iocs.#.ioc_type'] == 'ip'
```

**Option 2 — Single-quoted YAML string (double the inner single quotes)**:
```yaml
cel_expression: '!cs.cidr.valid(data[''iocs.#'']) && cs.string.find(data[''iocs.#''], ''[A-Fa-f0-9]{64}'') != data[''iocs.#'']'
```

**Option 3 — Block scalar (safest for complex expressions)**:
```yaml
cel_expression: >-
    !cs.cidr.valid(data['iocs.#'])
    && cs.string.find(data['iocs.#'], '[A-Fa-f0-9]{64}') != data['iocs.#']
```

### When quoting is required

You MUST quote the CEL expression if it contains:
- `!` at the start (YAML interprets as tag)
- `:` followed by space (YAML key-value separator)
- `#` not inside quotes (YAML comment)
- `{` or `}` at the start (YAML flow mapping)
- `[` or `]` at the start (YAML flow sequence)

### `display` array quoting

The `display` field often contains HTML-escaped versions of the expression.
CrowdStrike's export uses `&#39;` for single quotes and `&amp;` for ampersands:

```yaml
display:
    - '!cs.cidr.valid(data[&#39;iocs.#&#39;]) &amp;&amp; ...'
```

When authoring manually, use plain human-readable text instead:
```yaml
display:
    - IOC type is IP address
```

---

## CEL vs FQL expressions in conditions

Fusion workflows support **two** condition syntaxes — don't confuse them:

| YAML key | Language | Use case |
|----------|----------|----------|
| `cel_expression` | CEL | Data comparisons, type checks, string matching |
| `expression` | FQL-style | Field membership checks (e.g., group inclusion) |

**FQL-style example**:
```yaml
expression: GetUserIdentityContext.Groups:!['SkipCrowdStrikeWorkflows']
```
This checks that the Groups array does NOT contain "SkipCrowdStrikeWorkflows".

**Important**: Only `expression` (FQL-style) supports the `else` branch.
With `cel_expression`, model mutually exclusive conditions as parallel branches.

---

## Common patterns

### Type routing
```yaml
conditions:
    is_ip:
        cel_expression: data['iocs.#.ioc_type'] == 'ip'
        next: [ProcessIP]
    is_sha256:
        cel_expression: data['iocs.#.ioc_type'] == 'sha256'
        next: [ProcessSHA256]
    is_domain:
        cel_expression: data['iocs.#.ioc_type'] == 'domain'
        next: [ProcessDomain]
```

### IOC type detection without enum
```yaml
conditions:
    is_ip:
        cel_expression: cs.cidr.valid(data['iocs.#'])
    is_sha256:
        cel_expression: cs.string.find(data['iocs.#'], '[A-Fa-f0-9]{64}') == data['iocs.#']
    is_domain:
        cel_expression: "!cs.cidr.valid(data['iocs.#']) && cs.string.find(data['iocs.#'], '[A-Fa-f0-9]{64}') != data['iocs.#']"
```

### Conditional JSON body building
```yaml
json:
    data:
        - |-
          ${
              cs.map.merge([
                  {"searchReason": data['searchReason']},
                  (data['from'] != null && data['from'] != "" ? {"from": data['from']} : {})
              ])
          }
```
