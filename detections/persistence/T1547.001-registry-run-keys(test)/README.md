# Windows Startup Folder Persistence via Sysmon

> **Technique**: T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
> **Tactic**: Persistence (TA0003)
> **Severity**: High
> **Status**: Stable

---

## Goal

Detect an adversary establishing persistence on a Windows host by dropping an executable, script, or shortcut into one of the standard Windows Startup folders. On every subsequent user logon, Windows automatically executes all items in these folders, giving the adversary a foothold that survives reboots and logoffs without requiring a registry Run key, service, or scheduled task.

This rule covers the file-write half of T1547.001 — the sibling registry Run-key detection covers the registry half.

---

## Categorisation

| Field | Value |
|---|---|
| ATT&CK Tactic | Persistence (TA0003) |
| ATT&CK Technique | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder (T1547.001) |
| Data Source | Sysmon Event ID 11 (FileCreate) / MDE `DeviceFileEvents` |
| Log Category | `file_event` (Sigma logsource) |
| Platform | Windows |

---

## Strategy Abstract

The rule monitors for `FileCreate` events (Sysmon EID 11 / MDE `DeviceFileEvents`) where the target file path falls under either the per-user or all-users Startup folder — matched via the shared path fragment `\Start Menu\Programs\Startup\` — AND the file carries an extension associated with executable or script content: `.bat`, `.cmd`, `.com`, `.exe`, `.hta`, `.js`, `.jse`, `.lnk`, `.ps1`, `.scr`, `.url`, `.vbe`, `.vbs`, `.wsf`. A small exclusion strips events where the creating process is `msiexec.exe`, which is the dominant source of legitimate startup-item creation in most environments. Any write from a process that is not excluded — especially from user-writable paths like `%TEMP%`, `%APPDATA%`, or `%USERPROFILE%\Downloads` — is surfaced for analyst review.

The extension list is intentionally broad in the initial deployment. The goal is to surface all writes with executable-capable extensions and learn the environment's baseline before narrowing scope. Extension-based tuning should follow a 7-day FP observation period.

---

## Technical Context

### Attack Mechanics

Windows automatically executes all items in two Startup folder locations at every user logon:

```
Per-user (no elevation required to write):
C:\Users\[Username]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup

All-users / machine-wide (requires admin write access):
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp
```

An adversary with write access to the per-user path (no privilege required) or the all-users path (administrative rights required) can place a payload — a script, executable, or `.lnk` shortcut pointing at one — and it executes at the next logon with the privileges of the logging-on user.

This technique appears across commodity malware, RATs, and nation-state tooling as a primary or fallback persistence mechanism. Its appeal: it requires no registry modification, no service installation, and no scheduled task creation — only a file write and a reboot or logoff/logon cycle.

The technique is a structurally distinct vector within T1547.001, which also covers registry Run keys. The two vectors have completely different telemetry (`file_event` vs `registry_set`) and different FP profiles. They cannot be collapsed into a single rule without significantly complicating the logic and tuning of each — see the sibling registry rule.

### Telemetry

**Sysmon Event ID 11** (FileCreate) fires when a file is created or overwritten. Key fields:

| Sysmon Field | Sigma Field | Description |
|---|---|---|
| `TargetFilename` | `TargetFilename` | Full path and filename of the file being created |
| `Image` | `Image` | Full path of the process that created the file |
| `User` | `User` | Account responsible for the write (Sysmon 13.30+) |
| `ProcessId` | `ProcessId` | PID of the creating process |
| `CreationUtcTime` | — | Original creation timestamp; relevant for timestomping correlation via EID 2 |

In MDE's `DeviceFileEvents` table, the equivalent fields are `FolderPath` (full path including filename), `InitiatingProcessFolderPath`, `InitiatingProcessFileName`, `InitiatingProcessAccountName`, and `ActionType` (filter to `FileCreated`).

Sysmon must be configured to capture file events (EID 11) — confirm `<FileCreate>` is enabled in the Sysmon configuration. The lab uses a config derived from the SwiftOnSecurity baseline.

### Detection Logic

The rule uses `all of selection_*` — both conditions must be true for an alert to fire:

1. **`selection_path`**: `TargetFilename` contains `\Start Menu\Programs\Startup\`. A single substring covers both Startup paths since the per-user and all-users paths share this tail segment.

2. **`selection_ext`**: `TargetFilename` endswith one of the 14 listed extensions. These were chosen because they can be executed directly or via a Windows scripting host at logon. `.lnk` is included because it auto-runs its target — legitimately common, but a `.lnk` written to Startup from a non-installer process is worth reviewing.

The `filter_known_good` exclusion removes `msiexec.exe`-originated writes. The list is kept minimal; per-installer tuning is expected after the FP baseline observation period.

---

## Blind Spots & Assumptions

**Assumptions:**

- Sysmon 15.x is deployed on the host with a configuration that enables file event collection (EID 11).
- Sysmon logs are forwarded to the SIEM within a reasonable time window (≤15 minutes).
- The adversary is creating the Startup folder item through standard Windows API calls rather than a raw disk write.

**Blind Spots:**

- **Expected-extension masquerade** — an adversary using a normally-trusted extension (e.g. a `.lnk` shortcut whose target is a malicious payload) will fire the rule, but `.lnk` is common enough from legitimate installs that it carries the highest FP rate of any listed extension. This becomes the single most important blind spot once extension-based tuning narrows the list.
- **Modify-in-place of an existing Startup item** — overwriting an existing Startup file or repointing an existing `.lnk`'s target path may not generate a clean EID 11 `FileCreate` if the file already exists. The create-vs-overwrite semantics of EID 11 should be confirmed with a lab test.
- **Trusted process / LOLBIN as writer** — a signed updater, installer, or `explorer.exe` (user drag-and-drop) writing the file blends into the legitimate FP baseline and weakens any `Image`-based filtering. These cases require content inspection of the dropped file itself.
- **Registry vector** — an adversary who uses a Run/RunOnce key instead of the Startup folder sidesteps this rule entirely. Covered by the sibling registry Run-key rule — both halves of T1547.001 are needed for complete coverage.
- **Timestomping the dropped file** — backdating the file's creation timestamp (a Sysmon EID 2 signal) to blend in with legitimate Startup items evades time-window hunts. Correlate EID 2 against EID 11 events when timestomping is suspected.

---

## False Positives

- **Tray / auto-start applications** — Spotify, Steam, OneDrive, Microsoft Teams, and similar applications legitimately drop a startup shortcut (`.lnk`) during installation or first launch. These typically originate from per-application installer processes under `C:\Users\...\AppData\Local\Temp\` or `C:\Program Files\`.
- **Users manually placing shortcuts** — a user dragging an application icon into their own Startup folder via Explorer generates an EID 11 event from `explorer.exe`.
- **GPO / login scripts** — endpoint management tooling (Intune, SCCM, GPO) may deploy startup items as part of policy. These originate from well-known management process paths.
- **In-house line-of-business applications** — internal tooling that self-registers a Startup entry during installation.

Tune by adding known-good `Image` path prefixes to `filter_known_good` after reviewing your environment's baseline. Do not add overly broad prefixes (e.g. all of `C:\Program Files\`) — adversary payloads placed in subdirectories would be excluded.

---

## Priority / Severity

**Severity: High**

Startup folder persistence is trivial to implement for the per-user path (no elevation required), survives reboots and logoffs, and is used across a broad threat spectrum — from commodity RATs and loaders to targeted implants. Detection coverage here is a table-stakes requirement alongside the registry Run-key rule.

The rule carries an `experimental` status because the extension list is intentionally broad pending a 7-day FP baseline observation. Severity is rated `high` rather than `critical` to reflect the moderate expected FP rate from legitimate application installs. The rating will be revisited after the baseline observation period confirms the real-world alert volume.

---

## Validation

See [validation.md](validation.md) for the full test record including captured lab log evidence.

**Tests used**: Atomic Red Team T1547.001 — Test 1 (JSE file write to Startup) and Test 4 (LNK shortcut write to Startup)
**Commands**:
- Test 1: `Copy-Item "...\jsestartup.jse" "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\jsestartup.jse"`
- Test 4: PowerShell WScript.Shell shortcut creation targeting `calc.exe`
**Result**: Rule fired on JSE file creation. Sysmon EID 11 events captured. LNK evidence pending re-capture.
**Evidence**: See `validation.md` §3 — Lab Log Evidence.

---

## Response

When this alert fires, an analyst should:

1. **Identify the writing process** — check `Image` (Sysmon) or `InitiatingProcessFolderPath` (MDE). Is this a known installer, updater, or management agent? Writes from user-writable paths (`%TEMP%`, `%APPDATA%`, `%USERPROFILE%\Downloads`) are a strong indicator of malicious activity.

2. **Examine the dropped file** — what is the file? Does it exist on disk? Is it signed by a trusted publisher? For `.lnk` files, inspect the shortcut's target path. Use `DeviceFileEvents` or live response to retrieve the file for analysis.

3. **Review the process tree** — what spawned the process that wrote the file? Look for suspicious parent/child chains: `winword.exe → powershell.exe`, `explorer.exe → wscript.exe`, or `browser → cmd.exe` writing to a Startup folder are all suspicious patterns.

4. **Check whether the payload has already executed** — if a logon occurred after the file write, look for process creation events originating from the Startup folder path. The payload may already be running.

5. **Check for lateral spread** — is the same Startup folder filename appearing on multiple hosts? Query `DeviceFileEvents` across `DeviceName` to identify spread.

6. **Correlate with other activity** — look ±5 minutes from the file write for network connections, additional file drops, registry modifications, or other persistence mechanisms being established in the same session.

7. **Contain if malicious** — isolate the host via MDE live response or network quarantine. Preserve the Startup folder contents and any related files. If the payload has already executed, capture memory. Open an IR ticket.

---

## References

- [MITRE ATT&CK — T1547.001](https://attack.mitre.org/techniques/T1547/001/)
- [Atomic Red Team — T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md)
- [SigmaHQ — file_event_win_susp_startup_folder_persistence.yml](https://github.com/SigmaHQ/sigma/blob/98781da19cf60c48ce6e7f2d3ad11c9ba389191a/rules/windows/file/file_event/file_event_win_susp_startup_folder_persistence.yml)
- [SigmaHQ — file_event_win_startup_folder_file_write.yml](https://github.com/SigmaHQ/sigma/blob/98781da19cf60c48ce6e7f2d3ad11c9ba389191a/rules/windows/file/file_event/file_event_win_startup_folder_file_write.yml)
- [Palantir ADS Framework](https://github.com/palantir/alerting-detection-strategy-framework)
