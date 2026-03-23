# LogScale Security Query Development Skill

This is a properly structured Claude Code skill for developing, optimizing, and troubleshooting CrowdStrike LogScale security queries.

## Structure

```
logscale-security-queries/
├── SKILL.md                      # Main skill file with YAML frontmatter (REQUIRED)
├── case-statements.md            # Comprehensive case statement syntax guide
├── troubleshooting.md            # Error catalog and debugging methodology
├── query-patterns.md             # Common detection patterns library
├── investigation-playbooks.md    # Structured hunting methodology
├── examples.md                   # Production-ready query examples
├── reference.md                  # CQL syntax quick reference
└── README.md                     # This file
```

## Installation

### For Claude Code

1. **Personal Skill (just for you)**:
   ```bash
   mkdir -p ~/.claude/skills/
   cp -r logscale-security-queries ~/.claude/skills/
   ```

2. **Project Skill (for your team)**:
   ```bash
   mkdir -p .claude/skills/
   cp -r logscale-security-queries .claude/skills/
   git add .claude/skills/
   git commit -m "Add LogScale security query skill"
   ```

3. **Verify Installation**:
   ```bash
   # Start Claude Code
   claude
   
   # Ask Claude:
   "What skills are available?"
   ```

## How It Works

The skill is **model-invoked** - Claude automatically uses it when you:
- Ask about LogScale queries
- Mention CQL syntax
- Request security detection logic
- Encounter query errors
- Ask about CrowdStrike security monitoring

**Trigger phrases that activate the skill**:
- "Write a LogScale query to..."
- "Fix this CQL syntax error..."
- "Build a detection for..."
- "Create a hunting query for..."
- "Why is my case statement failing?"

## Usage Examples

### Example 1: Build a new detection
```
You: "Create a LogScale query to detect failed login attempts from 
     international IPs with risk scoring"

Claude: [uses skill] Here's a query with proper case statement syntax,
        risk categorization, and geolocation enrichment...
```

### Example 2: Fix syntax errors
```
You: "This case statement keeps failing: [paste query]"

Claude: [uses skill, reads troubleshooting.md] The error is you're
        using > without test(). Here's the fix...
```

### Example 3: Get patterns
```
You: "Show me common patterns for privilege escalation detection"

Claude: [uses skill, reads query-patterns.md] Here are several
        patterns for detecting role assumptions and escalations...
```

## Progressive Disclosure

Claude reads files **only when needed**:
- **SKILL.md** - Always read first (concise overview)
- **case-statements.md** - When case statements are mentioned
- **troubleshooting.md** - When errors occur
- **query-patterns.md** - When asking for patterns
- **examples.md** - When requesting complete examples
- **investigation-playbooks.md** - When discussing investigations
- **reference.md** - When needing syntax reference

This keeps Claude's context efficient while providing deep expertise when needed.

## What's Different from the Original

### Original (Single File)
❌ No YAML frontmatter (required for Claude Code)
❌ 1000+ lines in one file
❌ Claude reads everything every time
❌ Not discoverable by name/description
❌ No progressive disclosure

### New Structure (Modular)
✅ Proper YAML frontmatter with name and description
✅ Concise main file (~150 lines)
✅ Claude reads only what's needed
✅ Auto-discovered based on description triggers
✅ Progressive disclosure for efficiency

## Key Improvements

1. **Proper Skill Format**: YAML frontmatter with name and description
2. **Focused Main File**: Quick start info only, points to references
3. **Progressive Disclosure**: Detailed info in separate files
4. **Better Organization**: Logical grouping by topic
5. **Efficient Context Usage**: Claude doesn't load everything at once

## Updating the Skill

Edit any file and restart Claude Code:

```bash
# Edit a reference file
code ~/.claude/skills/logscale-security-queries/case-statements.md

# Changes take effect next Claude Code session
claude
```

## Customization

Add your own patterns and examples:

1. Edit `query-patterns.md` to add your detection patterns
2. Edit `examples.md` to add your production queries
3. Edit `reference.md` to add custom functions
4. Commit changes if using project skill

## Skill Description

The skill description tells Claude when to use it:

```yaml
description: Develop, optimize, and troubleshoot CrowdStrike LogScale 
(Humio) security detection queries using CQL syntax. Use when writing 
LogScale queries, building security detections, creating threat hunting 
rules, fixing CQL syntax errors, or working with CrowdStrike EDR/Falcon 
security monitoring. Handles case statements, risk categorization, 
investigation playbooks, and actionable security outputs.
```

This includes:
- What it does (develop, optimize, troubleshoot)
- Technologies (LogScale, CQL, CrowdStrike)
- Use cases (queries, detections, hunting, errors)
- Key features (case statements, risk categorization, etc.)

## Troubleshooting

**Skill not activating?**
1. Check installation location (`~/.claude/skills/` or `.claude/skills/`)
2. Verify SKILL.md has proper YAML frontmatter
3. Restart Claude Code
4. Use trigger phrases like "LogScale query" or "CQL syntax"

**Want to test it?**
```
"Write a LogScale query with proper case statement syntax"
```

**Need to debug?**
```bash
# Run with debug logging
claude --debug
```

## Contributing

This skill is based on real-world security operations experience. To improve it:

1. Add your production queries to `examples.md`
2. Document new patterns in `query-patterns.md`
3. Add error fixes to `troubleshooting.md`
4. Share with your team via git

## License

This is your skill for your team. Customize freely.
