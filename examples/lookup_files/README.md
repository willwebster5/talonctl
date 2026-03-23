# Lookup File Templates

This directory contains YAML templates for NGSIEM lookup files. Lookup files enable static data correlation in detection rules, saved searches, and correlation rules.

## Overview

Lookup files are CSV or JSON files uploaded to CrowdStrike NGSIEM that can be referenced in FQL queries using functions like:
- `match()` - Match field values against lookup table
- `in()` - Check if value exists in lookup table
- `lookup()` - Retrieve values from lookup table

## Template Format

```yaml
type: lookup_file
name: "filename.csv"              # Actual filename in NGSIEM
description: "Description"
format: csv                       # or json
source: data/path/to/file.csv    # Relative path to data file
_search_domain: falcon            # Search domain (falcon, all, third-party, etc.)

schema:                           # Optional: for documentation
  - name: column_name
    type: string
    description: "Column description"

tags:
  - tag1
  - tag2
```

## File Size Limits

- **CSV files**: Maximum 209.7 MB
- **JSON files**: Maximum 104.9 MB

## Available Templates

### Identity & Access Management

1. **entraid_service_accounts.yaml**
   - Service account inventory
   - Correlate service account activity
   - Track ownership and privilege levels

2. **entraid_users.yaml**
   - User directory with trust scores
   - Enrich events with user context
   - Support behavioral analytics

3. **entraid_groups.yaml**
   - Security group memberships
   - Identify privileged group access
   - Track group-based permissions

## Usage in Detections

### Example 1: Correlate with Service Accounts

```yaml
search:
  filter: |
    #event_simpleName=UserLogon
    | match(field=UserName, table="entraid-service-accounts.csv",
            column=account_name, include=[owner, privilege_level])
    | privilege_level = "high"
```

### Example 2: Check User Trust Level

```yaml
search:
  filter: |
    #event.action=AssumeRole
    | match(field=user.name, table="entraid-users.csv",
            column=user_principal_name, include=[trust_level, department])
    | trust_level != "high"
```

### Example 3: Filter by Group Membership

```yaml
search:
  filter: |
    #event.action=GroupMembershipChange
    | match(field=group_id, table="entraid-groups.csv",
            column=group_id, include=[is_privileged])
    | is_privileged = true
```

## Deployment

Lookup files are deployed using the LookupFileProvider:

```bash
# Validate templates
python scripts/validate_templates.py --type lookup_file

# Plan deployment
python scripts/resource_deploy.py plan --resources=lookup_file

# Apply changes
python scripts/resource_deploy.py apply --resources=lookup_file
```

## Data Source Files

Actual CSV/JSON data files are stored in:
- `data/entraid_lookups/` - EntraID identity data
- `data/network_lookups/` - Network configuration data
- `data/asset_lookups/` - Asset inventory data

## Best Practices

1. **Keep data fresh**: Update lookup files regularly to maintain accuracy
2. **Version control**: Store data files in Git for change tracking
3. **Document schema**: Always include schema definition for clarity
4. **Test correlations**: Verify lookup file matches work in test queries
5. **Monitor size**: Keep files under size limits for optimal performance
6. **Use appropriate domains**: Choose the right search domain for your use case

## Maintenance

- Update data files as identity/asset data changes
- Review and clean up unused lookup files
- Monitor file sizes to stay within limits
- Test lookup file availability after deployment
