<!-- PHASE: Classify (Phase 3)
     LOADED BY: /soc classify
     PURPOSE: Known FP patterns with IOC signatures for evidence comparison.
     CRITICAL: This file is loaded AFTER investigation evidence is collected.
     Never load this file during intake or triage phases — doing so causes confirmation bias.
     UPDATE: Add new FP patterns after triage confirms FP with specific evidence. -->

# Known False Positive Patterns

Patterns loaded at Phase 3 (classify) for evidence comparison. Each pattern includes specific IOCs that must be matched against collected evidence — partial matches (e.g., "same user seen before") are INSUFFICIENT.

## AWS CloudTrail

<!-- Add your AWS CloudTrail FP patterns here. Examples: CI/CD automation, sandbox accounts, known service roles, cloud security IoA noise. -->

## Microsoft EntraID

<!-- Add your EntraID FP patterns here. Examples: admin consent flows, dynamic group changes, SA account activity, iCloud Private Relay. -->

## Network / DNS

<!-- Add your network/DNS FP patterns here. Examples: CDN traffic, OAuth token exchanges, VPN service discovery. -->

## CrowdStrike Endpoint / IMDS

<!-- Add your endpoint/IMDS FP patterns here. Examples: IMDS credential retrieval from jumphosts, legitimate software installs. -->

## PhishER / KnowBe4

<!-- Add your PhishER FP patterns here. Examples: known-good email domains, CDN auto-loads, redirect cloakers. -->

## Windows Admin Login Detection (NGSIEM)

<!-- Add your Windows admin login FP patterns here. Examples: new device OOBE setup. -->

## GitHub

<!-- Add your GitHub FP patterns here. Examples: branch cleanup after merge, direct push detection tuning status. -->

## CrowdStrike EDR

<!-- Add your EDR FP patterns here. Examples: legitimate software installs, WinRAR from explorer, USB personal use. -->
