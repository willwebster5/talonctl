<!-- LIVING DOCUMENT
When investigation reveals new environmental context (new service accounts,
changed infrastructure, new applications, unfamiliar network patterns),
suggest updates to the user. Never modify silently.

Format suggestions as:
[SUGGESTED UPDATE] Section: <section name> | Change: <what to add/modify> | Evidence: <what was observed during investigation>

Wait for user approval before editing this file. -->

# SOC AI Agent Environment Context

## Quick Reference for Detection Analysis
<!-- Add your quick reference here. Example fields:
- **Environment**: ~NNN users, cloud/hybrid, geographic distribution
- **SIEM**: Platform and detection coverage
- **Alert Volume**: Typical daily alert count
- **High-Risk Users**: Categories of privileged users
- **Critical Assets**: Key systems and data stores
-->

## Overview
This document provides environmental context for SOC AI Agents analyzing SIEM detections. It focuses on ingested data sources, baseline activities, and typical patterns to improve detection accuracy and reduce false positives.

## Organization Profile

<!-- Add your organization profile here: size, industry, infrastructure model (cloud/hybrid/on-prem). -->

## AWS Account Inventory

<!-- Add your AWS account inventory here. Format:
| Account Name | Account ID | Purpose | Risk Level |
|---|---|---|---|
-->

## Named Service Accounts

<!-- Add your named service accounts here. Format:
| Account | Platform | Purpose |
|---|---|---|
-->

## Known Activity Patterns

<!-- Add your known activity patterns here. Document normal admin activity, CI/CD patterns, developer workflows. -->

## Conditional Access Policies

<!-- Add your conditional access policy summary here. -->

## Network Context

<!-- Add your network context here: VPN provider, geographic restrictions, firewall rules, split tunneling policy. -->

## Business Context

<!-- Add your business context here: geographic distribution, business hours, user provisioning flow, security stack. -->

## Data Sources & Baseline Activity

### 1. Google Workspace & GCP
<!-- Add your Google Workspace/GCP context here. -->

### 2. AWS Infrastructure
<!-- Add your AWS infrastructure context here. -->

### 3. Network Security (VPN/SASE)
<!-- Add your network security context here. -->

### 4. Identity Provider (EntraID / Okta / etc.)
<!-- Add your IdP context here. -->

### 5. File Storage
<!-- Add your file storage context here. -->

## Environment Characteristics
<!-- Add your environment characteristics here: geographic distribution, provisioning flow, company size, security stack, SOC operations. -->

## Detection Considerations
<!-- Add your detection considerations here: high-value targets, primary threat scenarios, common false positives, critical monitoring areas. -->

---
*Last Updated: YYYY-MM-DD*
