# Splunk SOC Detection Lab

A home lab demonstrating the end-to-end workflow of a junior SOC analyst: ingesting Windows endpoint telemetry (Event Logs and Sysmon) and AWS cloud telemetry (CloudTrail) into Splunk Enterprise, authoring SPL-based detections aligned to MITRE ATT&CK and the ATT&CK Cloud Matrix, and validating each detection through controlled adversary emulation and live alert triage.

> **Status:** Endpoint and cloud detection authoring and validation complete. Scheduled alerts operational. Dashboard pending.

---

## Architecture

| Layer | Component |
|---|---|
| Endpoint telemetry | Windows Event Logs (Application, Security, System) + Sysmon with [SwiftOnSecurity config](https://github.com/SwiftOnSecurity/sysmon-config) |
| Cloud telemetry | AWS CloudTrail management events, ingested via S3 polling using the [Splunk Add-on for AWS](https://splunkbase.splunk.com/app/1876) |
| Ingestion | Splunk Enterprise 10 on Windows 11, file-based `inputs.conf`, Splunk Add-on for Sysmon, Splunk Add-on for AWS |
| Analytics | SPL detections mapped to MITRE ATT&CK (endpoint) and ATT&CK Cloud Matrix |
| Validation | Controlled adversary emulation; live alert triage with documented false-positive analysis |
| Operational | Scheduled alerts with cron-based execution and per-detection severity tuning |

---

## Detections

Each detection is in [`detections/`](detections/) as a standalone `.spl` file with inline comments explaining the logic, MITRE mapping, and false-positive considerations.

### Endpoint detections (Windows + Sysmon)

| # | Detection | MITRE ATT&CK | Data Source |
|---|---|---|---|
| 1 | [Failed logon brute force](detections/01-brute-force.spl) | [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/) | `WinEventLog:Security` (EventCode 4625) |
| 2 | [Suspicious PowerShell execution](detections/02-suspicious-powershell.spl) | [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/) | Sysmon EventCode 1 |
| 3 | [Process from suspicious location](detections/03-suspicious-location.spl) | [T1036 — Masquerading](https://attack.mitre.org/techniques/T1036/) | Sysmon EventCode 1 |
| 4 | [Script host spawning shell](detections/04-script-host-shell.spl) | [T1566 — Phishing](https://attack.mitre.org/techniques/T1566/) | Sysmon EventCode 1 |
| 5 | [Rare process by parent](detections/05-rare-process.spl) | Anomaly hunting (multi-technique) | Sysmon EventCode 1 |

### Cloud detections (AWS CloudTrail)

| # | Detection | MITRE ATT&CK | Data Source |
|---|---|---|---|
| 6 | [AWS root account usage](detections/06-aws-root-usage.spl) | [T1078.004 — Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/) | AWS CloudTrail |
| 7 | [Console login without MFA](detections/07-aws-login-no-mfa.spl) | [T1078.004 — Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/) | AWS CloudTrail |
| 8 | [IAM user or access key creation](detections/08-aws-iam-creation.spl) | [T1136.003 — Create Cloud Account](https://attack.mitre.org/techniques/T1136/003/) | AWS CloudTrail |

---

## Validation

Each detection was validated against controlled adversary emulation in the lab consisting of benign payloads exhibiting the same behavioral patterns as real adversary tradecraft. Empty results were evaluated against the principle that empty is the correct state for such detection telemetry. Evidence screenshots and trigger documentation live in [`screenshots/`](screenshots/).

| Detection | Trigger Method |
|---|---|
| 1. Brute force | Repeated `runas` with bad credentials → EventCode 4625 |
| 2. Suspicious PowerShell | `Write-Host` payload base64-encoded + executed via `-EncodedCommand` |
| 3. Suspicious location | `cmd.exe` copied to `%TEMP%` under a different name and executed |
| 4. Script host shell | VBScript via `wscript.exe` spawning `cmd.exe` |
| 5. Rare process | Observed naturally on host (hunting query, no trigger needed) |
| 6. AWS root usage | Not triggered; empty result is the desired state per AWS best practice |
| 7. Console login no MFA | Deliberate sign-out and sign-in to AWS console |
| 8. IAM creation | Created throwaway IAM user, attached policy, generated access key, deleted |

A live alert from Detection 2 fired on a VS Code auto-update during the lab. Full triage workflow, incluiding initial inspection, pivot to surrounding events, process tree reconstruction, root cause determination, is documented in [triage notes](screenshots/triage-notes.md).

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

**Splunk 10 web UI regression.** The "Local event log collection" page in Settings → Data Inputs returns a 404 in Splunk Enterprise 10.x on Windows. Worked around by configuring all Windows Event Log inputs directly via `inputs.conf` which is the preferred admin workflow regardless.

**CloudTrail data-availability boundary.** Initial validation of the AWS detections returned no results despite having generated activity (IAM user creation, console logins) before enabling CloudTrail. CloudTrail records only events from the moment the trail is enabled forward; pre-trail activity is invisible and unrecoverable. The detections were validated by deliberately re-triggering the relevant API calls after CloudTrail was confirmed flowing. Production implication: CloudTrail-from-day-one is part of every cloud security baseline because retroactive visibility is impossible.

---

## Roadmap

- [x] Splunk Enterprise on Windows 11
- [x] Windows Event Log ingestion via `inputs.conf`
- [x] Sysmon installation with SwiftOnSecurity config
- [x] Splunk Add-on for Sysmon, field extraction validated
- [x] Five endpoint SPL detections authored and MITRE-mapped
- [x] Adversary emulation triggers + evidence screenshots
- [x] Scheduled alerts for each detection (cron-based, severity-tuned)
- [x] AWS CloudTrail ingestion via S3 polling
- [x] Three cloud SPL detections authored and ATT&CK Cloud Matrix-mapped
- [x] Live alert triage with documented root cause analysis
- [ ] Security overview dashboard
- [ ] Splunk Security Essentials integration notes

---

## References

- [MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
- [Sysmon by Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- [AWS CloudTrail documentation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html)
- [Splunk Add-on for AWS](https://splunkbase.splunk.com/app/1876)
- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)

---

*Built by Ryan Howley (https://github.com/ryanh610) - May 2026*