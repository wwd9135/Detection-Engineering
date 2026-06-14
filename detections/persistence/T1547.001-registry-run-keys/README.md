# Windows Registry Run Key Persistence via Sysmon

> **Technique**: T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
> **Tactic**: Persistence (TA0003)
> **Severity**: High
> **Status**: Stable

---

## Goal

Detect an adversary establishing persistence on a Windows host by writing an executable path into one of the standard registry Run or RunOnce autostart keys. When a user logs on (Run) or at next boot (RunOnce), Windows automatically executes the value's data as a command, giving the adversary a foothold that survives reboots and user logoffs without requiring a service, scheduled task, or startup folder entry.

---

## Categorisation

| Field | Value |
|---|---|
| ATT&CK Tactic | Persistence (TA0003) |
| ATT&CK Technique | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder (T1547.001) |
| Data Source | Sysmon Event ID 13 (RegistryEvent — Value Set) / MDE `DeviceRegistryEvents` |
| Log Category | `registry_set` (Sigma logsource) |
| Platform | Windows |

---

## Strategy Abstract

The rule monitors for `RegistryValueSet` events (Sysmon EID 13 / MDE `DeviceRegistryEvents`) where the target key path contains one of the four canonical Run/RunOnce paths under `HKCU` or `HKLM`, including the 32-bit WOW6432Node reflection. A small exclusion list removes events originating from `msiexec.exe`, which is the dominant source of legitimate run-key writes in most environments. Any write from a process that is not in the exclusion list — especially from unusual paths like `%TEMP%`, `%APPDATA%`, or `%USERPROFILE%\Downloads` — is surfaced for analyst review.

---

## Technical Context

### Attack Mechanics

The Windows registry contains several keys whose values are executed automatically at logon or boot. The most commonly abused are:

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
```

An adversary with write access to `HKCU\...\Run` (no privilege required) or `HKLM\...\Run` (requires administrative rights) can set a value whose data points to their payload. On next logon, Windows will execute that command with the privileges of the logging-on user (`HKCU`) or SYSTEM (`HKLM`).

This technique appears across nearly every malware family and threat actor: from commodity loaders (Emotet, QakBot, Agent Tesla) to nation-state implants. Its ubiquity makes it a priority detection target.

### Telemetry

**Sysmon Event ID 13** (RegistryEvent — Value Set) fires whenever a registry value is written. Key fields:

| Sysmon Field | Sigma Field | Description |
|---|---|---|
| `TargetObject` | `TargetObject` | Full registry key path including value name |
| `EventType` | `EventType` | Always `SetValue` for EID 13 |
| `Image` | `Image` | Full path to the process making the write |
| `Details` | `Details` | The data written to the registry value (the payload path) |
| `ProcessId` | `ProcessId` | PID of the writing process |

In MDE's `DeviceRegistryEvents` table, the equivalent fields are `RegistryKey`, `RegistryValueName`, `RegistryValueData`, and `InitiatingProcessFolderPath`.

Sysmon must be configured to capture registry events (EIDs 12, 13, 14) — this is disabled by default in minimal configurations. The lab uses a config derived from the SwiftOnSecurity baseline.

### Detection Logic

The rule selects all `SetValue` events where `TargetObject` contains any of the four Run/RunOnce path strings. This is intentionally broad — the goal is to surface any write to these keys and then rely on the exclusion list and analyst triage to handle FPs, rather than trying to enumerate all malicious patterns (which would create a brittle, easily-evaded rule).

The `filter_empty_value` exclusion drops events where `Details` is empty, which can occur when a key is being deleted and the deletion is logged as a set with no data.

---

## Blind Spots & Assumptions

**Assumptions:**

- Sysmon 15.x is deployed on the host with a configuration that enables registry event collection (EIDs 12/13/14).
- Sysmon logs are forwarded to Microsoft Sentinel within a reasonable time window (≤15 minutes) via the Azure Monitor Agent.
- The adversary is writing the run key through standard Windows API calls (`RegSetValueEx`) rather than directly manipulating the registry hive file.

**Blind Spots:**

- **Offline hive manipulation** — an adversary who mounts and edits the `NTUSER.DAT` or `SOFTWARE` hive as a raw file (e.g., from a WinPE environment or via a bootkit) will not generate a `RegistryValueSet` event.
- **Wow6432Node via 64-bit process** — a 64-bit process writing to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` will NOT be redirected to WOW6432Node. The current rule covers both paths, but the WOW6432Node variant is only meaningful for 32-bit processes. Double-check field mapping if the pipeline translates paths.
- **`RunServices` and `RunServicesOnce`** — older, less-common Run key variants are not covered by this rule. They exist but are rarely used by modern malware.
- **Startup folder** — `T1547.001` also covers writing to the Windows Startup folder (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`). This rule does NOT cover that vector — see a separate file-creation-based rule.
- **Registry symbolic links / key aliasing** — an adversary who uses registry symbolic links to redirect a write through an alternate key path will evade this rule.

---

## False Positives

- **Software installers** — Chrome, Firefox, Zoom, Slack, and many others write run-key entries for auto-update agents during installation. These typically originate from `msiexec.exe` (excluded) or per-application installer processes under `C:\Users\{user}\AppData\Local\Temp\`.
- **Endpoint management** — SCCM, Intune, and similar tools may write run keys as part of policy application. These originate from well-known management paths.
- **AV / EDR products** — some security products write their own run-key entries for tamper protection or update agents.
- **Developer testing** — engineers building software that registers a run-key entry will trigger this rule from development directories.

Tune by adding known-good `Image` path prefixes to `filter_known_installers` after reviewing your environment's baseline. Do not add overly broad path prefixes (e.g., all of `C:\Program Files\`) — adversary payloads placed in subdirectories would be excluded.

---

## Priority / Severity

**Severity: High**

Run-key persistence is a foundational technique used across a wide range of threat actors and malware families. It requires minimal privileges for `HKCU`, survives reboots, and is trivial to implement. Detection coverage here is a table-stakes requirement.

The `high` rather than `critical` rating reflects the moderate FP rate — most environments generate some legitimate run-key writes from software installers. An analyst response is always required, but the urgency is calibrated against the FP burden. Rules that are too noisy become ignored.

---

## Validation

See [validation.md](validation.md) for the full test record including synthetic log evidence.

**Test used**: Atomic Red Team T1547.001 — Test 1 ("Add/Modify Run-Key Entry")
**Command**: `reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "AtomicTest" /t REG_SZ /d "C:\Temp\AtomicRedTeam\payload.exe" /f`
**Result**: Rule fired. Sysmon EID 13 event captured. KQL query returned the event.
**Evidence**: See `validation.md` §3 — Synthetic Log Evidence.

---

## Response

When this alert fires, an analyst should:

1. **Identify the writing process** — check `Image` (Sysmon) or `InitiatingProcessFolderPath` (MDE). Is this a known installer? Is the path user-writable (e.g., `%TEMP%`, `%APPDATA%`)? User-writable paths are a strong indicator of malicious activity.

2. **Examine the value data** — what does the run-key value point to? Does that file exist on disk? Is it signed by a trusted publisher? Use `DeviceFileEvents` or live response to check.

3. **Review the process tree** — what spawned the process that made the registry write? Look for suspicious parent/child chains: `Office → wscript → reg.exe`, `winword.exe → cmd.exe`, or `explorer.exe → powershell.exe` writing to Run keys are all suspicious.

4. **Check for lateral spread** — is the same run-key value name or payload path appearing on multiple hosts? Query `DeviceRegistryEvents` across `DeviceName` to identify spread.

5. **Correlate with other activity** — look ±5 minutes from the registry write for network connections, file drops, or other persistence mechanisms being established in the same session.

6. **Contain if malicious** — isolate the host via MDE live response or network quarantine. Preserve the registry hive, any dropped payload, and memory if the process is still active. Open an IR ticket.

---

## References

- [MITRE ATT&CK — T1547.001](https://attack.mitre.org/techniques/T1547/001/)
- [Microsoft Docs — Run and RunOnce Registry Keys](https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys)
- [Atomic Red Team — T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md)
- [SigmaHQ — registry_persistence_run_key rules](https://github.com/SigmaHQ/sigma/tree/master/rules/windows/registry)
- [Palantir ADS Framework](https://github.com/palantir/alerting-detection-strategy-framework)
