# Splunk SOC Detection Lab

A home lab demonstrating the end-to-end workflow of a junior SOC analyst: ingesting Windows Event Logs and Sysmon telemetry into Splunk Enterprise, authoring SPL-based detections aligned to MITRE ATT&CK, and validating each detection through controlled adversary emulation.

> **Status:** Detection authoring complete. Validation screenshots and dashboard in progress: see [roadmap](#roadmap).

---

## Architecture

| Layer | Component |
|---|---|
| Endpoint telemetry | Windows Event Logs (Application, Security, System) + Sysmon with [SwiftOnSecurity config](https://github.com/SwiftOnSecurity/sysmon-config) |
| Ingestion | Splunk Enterprise 10 on Windows 11, file-based `inputs.conf`, Splunk Add-on for Sysmon |
| Analytics | SPL detections mapped to MITRE ATT&CK |
| Validation | Controlled adversary emulation; screenshot evidence per detection |
| Operationalization | Scheduled alerts and a security overview dashboard |

---

## Detections

Each detection is in [`detections/`](detections/) as a standalone `.spl` file with inline comments explaining the logic, MITRE mapping, and false-positive considerations.

| # | Detection | MITRE ATT&CK | Data Source |
|---|---|---|---|
| 1 | [Failed logon brute force](detections/01-brute-force.spl) | [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/) | `WinEventLog:Security` (EventCode 4625) |
| 2 | [Suspicious PowerShell execution](detections/02-suspicious-powershell.spl) | [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/) | Sysmon EventCode 1 |
| 3 | [Process from suspicious location](detections/03-suspicious-location.spl) | [T1036 — Masquerading](https://attack.mitre.org/techniques/T1036/) | Sysmon EventCode 1 |
| 4 | [Script host spawning shell](detections/04-script-host-shell.spl) | [T1566 — Phishing](https://attack.mitre.org/techniques/T1566/) | Sysmon EventCode 1 |
| 5 | [Rare process by parent](detections/05-rare-process.spl) | Anomaly hunting (multi-technique) | Sysmon EventCode 1 |

---

## Ingestion configuration

The lab ingests two distinct Windows data sources via a single `inputs.conf`. See [`configs/inputs.conf`](configs/inputs.conf) for the full file.

Key design choices:
- `renderXml = true` on the Sysmon stanza preserves the structured XML payload, which is required for the Splunk Add-on for Sysmon to extract fields like `Image`, `ParentImage`, `CommandLine`, and `Hashes`.
- The Sysmon channel is sent to `index=main` for lab simplicity. In production, Sysmon should land in a dedicated index for retention and access-control reasons.

---

## Engineering notes

A few real-world Splunk admin issues encountered and resolved during the build:

**TA-driven sourcetype rewriting.** After installing the Splunk Add-on for Sysmon, all existing searches against `sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"` returned zero results. The add-on silently rewrites the sourcetype to lowercase `xmlwineventlog` on ingest. Diagnosed via `index=* | stats count by sourcetype` and updated all detections accordingly.

**Splunk 10 web UI regression.** The "Local event log collection" page in Settings → Data Inputs returns a 404 in Splunk Enterprise 10.x on Windows. Worked around by configuring all Windows Event Log inputs directly via `inputs.conf` — which is the preferred admin workflow regardless.

---

## Roadmap

- [x] Splunk Enterprise on Windows 11
- [x] Windows Event Log ingestion via `inputs.conf`
- [x] Sysmon installation with SwiftOnSecurity config
- [x] Splunk Add-on for Sysmon, field extraction validated
- [x] Five SPL detections authored and MITRE-mapped
- [ ] Adversary emulation triggers + evidence screenshots
- [ ] Scheduled alerts for each detection
- [ ] Security overview dashboard
- [ ] Splunk Security Essentials integration notes

---

## References

- [MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
- [Sysmon by Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)

---

*Built by Ryan Howley (https://github.com/ryanh610) — May 2026*