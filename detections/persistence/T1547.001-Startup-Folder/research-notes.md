# Research Notes — T1547.001 Startup Folder Persistence

*Working notes compiled during rule development. Not polished — this is the actual research trail.*

---

## Starting Point

**Hypothesis**: An adversary can achieve persistence on a Windows host by dropping (or linking) an executable or script into one of the standard Startup folders. Anything placed in those folders is executed automatically at the next logon, with the privileges of the logging-on user — no service, scheduled task, or registry write required. A rule watching **Sysmon EID 11 (FileCreate)** for writes into either Startup folder path should catch a broad range of implementations.

**Why a separate rule (split from the registry Run-key rule)?**
- T1547.001 covers **two distinct vectors** — registry Run/RunOnce keys *and* the Startup folder — with completely different telemetry (`registry_set` vs `file_event`) and different false-positive profiles. Keeping them as separate rules keeps each one's logic and tuning clean.
- The Startup-folder vector requires **no registry write at all**, so the registry rule is structurally blind to it. Both rules are needed for real T1547.001 coverage.
- Good telemetry coverage via Sysmon EID 11 + MDE `DeviceFileEvents` — a data source I trust.
- Low barrier for the attacker (per-user folder needs no elevation), and Atomic Red Team has clean tests I can run.

---

## ATT&CK Page Notes

Pulled from [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/) on 2026-06-14.

### Mechanism
Adversaries drop a malicious file (or a `.lnk` shortcut pointing at one) straight into a Startup folder. Windows then executes that item automatically on every logon, giving persistence that survives reboots and logoffs.

### Detection ideology
Detect **all** file creations under the Startup folder paths and start deliberately broad / high-FP. The point of the high initial FP rate is to *learn what legitimately lands in these folders in this environment first*, then tune out the expected traffic. Once the baseline is understood, the focus narrows onto **extension types** — `.lnk` is expected and common, whereas `.ps1`, `.exe`, `.vbs`, `.bat`, `.js`, `.scr` etc. landing here are typically not. (Final allow/deny extension split is environment-dependent — decided after the baseline observation; see Open Questions.)

### ATT&CK lists two Startup folder paths
1. **Per-user** (no elevation required to write):
   `C:\Users\[Username]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`
2. **All-users / machine-wide** (requires admin to write):
   `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`

Both paths should be covered by the rule — same telemetry, just different scope.

---

## Existing Community Rules Reviewed

Reviewed for field usage and logic patterns — wrote my own rule from scratch.

| Source | Rule name | Notes |
|---|---|---|
| SigmaHQ — [link](https://github.com/SigmaHQ/sigma/blob/98781da19cf60c48ce6e7f2d3ad11c9ba389191a/rules/windows/file/file_event/file_event_win_susp_startup_folder_persistence.yml) | `file_event_win_susp_startup_folder_persistence.yml` | Identifies the key signals but is very broad. Good starting point but needs filtering for the environment. *(NB: my original notes named this `file_event_win_office_startup_persistence.yml`, which doesn't match the linked file — resolve which one I actually meant.)* |
| SigmaHQ — [link](https://github.com/SigmaHQ/sigma/blob/98781da19cf60c48ce6e7f2d3ad11c9ba389191a/rules/windows/file/file_event/file_event_win_startup_folder_file_write.yml) | `file_event_win_startup_folder_file_write.yml` | More holistic — goes after specific file extensions. Potentially high FP if one of those extensions is legitimate in this environment (env-dependent). |

**Decision**: Write my own Sigma rule. Community rules either have broader scope (more noise) or more aggressive exclusion lists (more blind spots). Plan: **start minimal** (like rule 1 above — catch all writes to the Startup paths), then layer in **rule 2's extension-focused ideology** once I understand the baseline, to land on a higher-fidelity alert tuned to my environment.

---

## Data Source Research

### Sysmon Event ID 11 — FileCreate (primary event)
Fires when a file is created (or overwritten). Fields I care about:
- **`TargetFilename`** — the full path *and* name of the file being created. **This is the field the rule keys on** (match against the two Startup folder paths).
- **`Image`** — the full path of the **process that created the file** (i.e. *who* dropped it — `explorer.exe`, `powershell.exe`, a dropper, an installer, etc.). It is *not* the file being created. This is the field to filter / triage on. *(This is the bit I was unsure about — clarified.)*
- **`ProcessId`, `ProcessGuid`, `UtcTime`** — background info, useful for event correlation.
- **`User`** — recent Sysmon versions (13.30+) include the responsible user directly on EID 11, which reduces the need to correlate to another event just to attribute the write (see Open Questions).

### Sysmon Event ID 2 — FileCreateTime (correlation / enrichment only)
EID 2 fires when a process **changes a file's creation timestamp** — i.e. it's primarily a **timestomping** signal, *not* a normal file-create event. So this is enrichment, not the primary detection: useful for catching an adversary who drops a payload into Startup and then backdates it to blend in with legitimate files. Fields:
- **`User` / `UserId`** — worth correlating against the `ProcessId` from the EID 11 event to confirm the responsible user.
- **`TargetFilename`, `Image`** — to confirm the correlation lines up with the FileCreate event.
- **`UtcTime`** — worth grabbing for forensic validation / timeline reconstruction.

### MDE `DeviceFileEvents` (KQL — Sentinel / Defender XDR)
Supported on any MDE-onboarded device. Can be the main source of truth or used for extra context alongside Sysmon. Fields:
- **`ActionType`** — filter down to file *creation* only (`FileCreated`).
- **`FolderPath`** — the full path including the file name (the equivalent of `TargetFilename`).
- **`InitiatingProcessFolderPath`** — which process spawned/created the file (equivalent of `Image`).
- **`DeviceName`** — the host's name; gold in an enterprise environment for scoping spread.
- **`InitiatingProcessAccountDomain` + `InitiatingProcessAccountName`** — the account's domain and name; ties the activity back to a user. Strong pivot material for further investigation in Defender XDR / Sentinel.

---

## Atomic Red Team Test Reviewed

T1547.001 includes four relevant file-write tests. I ran Tests 1 and 4 — the two structurally distinct types. Tests 2 (VBS) and 3 (BAT) are identical in pattern to Test 1 and produce the same telemetry.

**Test 1 — JSE file write to all-users Startup** *(requires admin)*
```powershell
Copy-Item "$PathToAtomicsFolder\T1547.001\src\jsestartup.jse" `
  "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\jsestartup.jse"
```

**Test 2 — VBS file write to all-users Startup** *(requires admin)*
```powershell
Copy-Item "$PathToAtomicsFolder\T1547.001\src\vbsstartup.vbs" `
  "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\vbsstartup.vbs"
```

**Test 3 — BAT file write to all-users Startup** *(requires admin)*
```powershell
Copy-Item "$PathToAtomicsFolder\T1547.001\src\batstartup.bat" `
  "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\batstartup.bat"
```

**Test 4 — LNK shortcut write to per-user Startup** *(no elevation required)*
```powershell
$Target = "C:\Windows\System32\calc.exe"
$ShortcutLocation = "$home\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\calc_exe.lnk"
$WScriptShell = New-Object -ComObject WScript.Shell
$Create = $WScriptShell.CreateShortcut($ShortcutLocation)
$Create.TargetPath = $Target
$Create.Save()
```

These four tests cover the most common attack paths for this vector. Key takeaway: target the **mechanism** (file with an executable-capable extension landing in a Startup path) rather than specific filenames or hostnames, which are trivial for an attacker to vary. The extension + path combination is what matters.

---

## Potential Evasion Paths (noted for blind spots section)

1. **Expected-extension masquerade** — dropping a malicious item under a normally-trusted extension (e.g. a `.lnk` shortcut whose target is the real payload). This evades any detection that allow-lists specific extensions, and `.lnk` creation in Startup is common/legit enough that detecting the `.lnk` itself is high-FP. Likely the single most important blind spot for this rule.
2. **Modify-in-place of an existing legit item** — overwriting an existing Startup file, or repointing an existing `.lnk`'s target, may not generate a clean EID 11 *FileCreate* if the file already exists. Need to confirm FileCreate semantics on overwrite vs new-create (see Open Questions).
3. **Trusted process / LOLBIN as the writer** — a signed updater, installer, or `explorer.exe` (drag-and-drop) writing the file blends into the legitimate FP baseline, weakening any `Image`-based filtering.
4. **Choosing the registry vector instead** — an adversary who uses a Run/RunOnce key rather than the Startup folder sidesteps this rule entirely. Covered by the sibling registry rule — which is exactly why both halves of T1547.001 are needed.
5. **Timestomping the dropped file (EID 2)** — backdating the file's creation time to evade time-window hunts; ties back to why EID 2 correlation is worth pulling.

---

## Field Mapping Verification

Plan: confirm the Sysmon `file_event` logsource fields translate correctly through the pySigma `microsoft_xdr` pipeline into the MDE `DeviceFileEvents` schema, then review the compiled KQL manually (same process as rule 1). Mappings to verify:

| Sigma (file_event) | Expected MDE field | Status |
|---|---|---|
| `category: file_event` | `DeviceFileEvents`, `ActionType == "FileCreated"` | ☐ to verify |
| `TargetFilename` | `FolderPath` | ☐ to verify |
| `Image` | `InitiatingProcessFolderPath` | ☐ to verify |

Verification command (mirrors rule 1):
```bash
sigma convert -t kusto -p microsoft_xdr detections/persistence/T1547.001-startup-folder/rule.yml
```
Then eyeball the KQL output and compare against `rule.kql`.

---

## Open Questions
- [ ] Which extensions count as **expected** (`.lnk`) vs **suspicious** (`.exe`, `.ps1`, `.vbs`, `.bat`, `.js`, `.scr`, …)? Decide after the baseline observation period, not up front.
- [ ] One rule covering **both** Startup paths (per-user + all-users), or split? Leaning toward one rule — same telemetry, just different scope.
- [ ] Does Sysmon **EID 11 fire on overwrite/modify** of an existing Startup item, or only on a genuinely new file? Affects evasion path #2 — needs a lab test.
- [ ] Resolve the community-rule name/URL discrepancy in the table above (which SigmaHQ rule did I actually mean?).
- [ ] Does the newer Sysmon **`User` field on EID 11** remove the need to correlate with EID 2 purely for attribution?
- [ ] FP baseline: run in observe mode for ~7 days against normal lab activity (logons, software installs, Windows Update) and record alert volume + source processes before tuning — same approach as rule 1.
