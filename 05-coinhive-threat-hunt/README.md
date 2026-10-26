# 05 — Coinhive Cryptojacking Threat Hunt

## Overview

This project investigates suspected browser-based cryptocurrency mining using Splunk Enterprise and the Boss of the SOC (BOTS) v3 dataset.

The investigation follows the Coinhive cryptojacking scenario from the `splunk-bots-hunts` repository.

**Tools:** Splunk Enterprise, SPL  
**Dataset:** Splunk BOTS v3  
**Focus:** DNS threat hunting and endpoint identification

## Investigation Objectives

- Identify the internal host resolving Coinhive-related domains.
- Count unique Coinhive fully qualified domain names (FQDNs).
- Identify distinct mining endpoint domains.
- Identify the associated host MAC address.

## Findings

| Hunt | Result |
|---|---|
| Internal source IP | `192.168.247.131` |
| Unique Coinhive FQDNs | 6 |
| Unique mining endpoints | 5 |
| Host MAC address | `00:0C:29:B8:44:5E` |
| Host identified in reference scenario | `BSTOLL-L` |

All four results matched the expected answers in the reference investigation.

## Hunting Queries

### 1. Identify the Internal Host

```spl
index=* sourcetype=stream:dns coinhive.com src_ip=* earliest=-10y
| stats count by src_ip
| sort -count
| head 1
| fields src_ip
```

**Result:** `192.168.247.131`

### 2. Count Unique Coinhive Domains

```spl
index=* sourcetype=stream:dns query="*coinhive.com" earliest=-10y
| stats dc(query) as fqdn_count
| fields fqdn_count
```

**Result:** 6 unique FQDNs

### 3. Identify Mining Endpoints

```spl
index=* sourcetype=stream:dns query="ws*.coinhive.com" earliest=-10y
| stats dc(query) as endpoint_count
| fields endpoint_count
```

**Result:** 5 unique endpoint domains

### 4. Identify the Host MAC Address

```spl
index=* sourcetype=stream:dns coinhive.com src_mac=* earliest=-10y
| stats count by src_mac
| sort -count
| head 1
| fields src_mac
```

**Result:** `00:0C:29:B8:44:5E`

## Analysis

The DNS telemetry contains multiple Coinhive-related domain lookups, including five distinct mining endpoint names. The source IP and MAC address match the reference scenario's identification of `BSTOLL-L`.

These findings support further investigation of suspected browser-based cryptojacking. DNS evidence alone does not independently prove that cryptocurrency mining was actively taking place or establish how the script was delivered.

## MITRE ATT&CK

The reference scenario associates this activity with:

- **T1496 — Resource Hijacking**
- **T1059.007 — JavaScript**
- **T1071.001 — Web Protocols**
- **T1189 — Drive-by Compromise**

These are mappings from the reference scenario, not independently confirmed techniques based solely on the four DNS hunts.

## Evidence

Screenshots of the four Splunk hunt results are stored in the `screenshots/` directory.

- `01-internal-host.png`
- `02-unique-fqdns.png`
- `03-mining-endpoints.png`
- `04-host-mac.png`

## Reference

[Splunk BOTS Hunts — Scenario 03: BSTOLL-L Browser Cryptojacking](https://github.com/JacobRHess/splunk-bots-hunts/tree/main/scenarios/03-bstoll-coinhive-cryptojacking)

This project uses a public training dataset for cybersecurity learning and portfolio demonstration. It does not represent a real production incident.
