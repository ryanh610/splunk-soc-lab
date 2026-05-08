# Triage notes

## 2026-05-08 — T1059.001 alert: VS Code installer (false positive)

The Detection 2 alert fired on two PowerShell events spawned by a process running from %TEMP%. The parent process name (`CodeSetup-stable-<hash>.tmp`) and the `is-<id>.tmp` directory pattern identified it as an Inno Setup-based installer; specifically the Visual Studio Code standalone installer. The PowerShell invocations were checking for and removing the Microsoft Store version of VS Code before completing the standalone install. Legitimate installer behavior; matches all four indicators the detection keys on.

This is the routine false-positive shape for T1059.001 and T1036 detections in a developer workstation environment. Production tuning would exclude signed binaries from known publishers, or specifically allowlist the `*Setup-*.tmp` parent-process pattern with the understanding that this opens a small evasion window.

### Triage corroboration

Reconstructed the full installer process tree by pivoting from the alert events to surrounding Sysmon process-creation activity in the same time window. The chain (12:24:17 → 12:25:29) showed:

1. Running `Code.exe` spawned `CodeSetup-stable-<hash>.exe` with `/verysilent /update=...` flags. This confirms an auto-update was initiated by the running VS Code instance.
2. The installer extracted itself into `Temp\is-<id>.tmp\` (Inno Setup pattern) and re-launched.
3. `icacls.exe` set NTFS permissions on the new VS Code directory.
4. Four PowerShell invocations followed: check, remove, check, and install the AppX (Microsoft Store) version of VS Code. This conducts a standard cleanup to prevent dual-install conflicts.

Conclusion: legitimate auto-update; alert correctly classified as a false positive. Root cause documented.

Raw alert export: [false-positive-triage-vscode.csv](false-positive-triage-vscode.csv)
Process tree reconstruction: [triage-corroboration-vscode-update.csv](triage-corroboration-vscode-update.csv)