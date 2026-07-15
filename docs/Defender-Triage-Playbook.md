# Defender / AV Triage for Telemetry Generators — Field Notes

**Goal:** figure out *what* Defender is blocking, *which layer* it's blocking at, and the minimum change to get clean telemetry. Three block layers, each diagnosed and fixed differently:

| Layer | When it fires | Loses telemetry? |
|---|---|---|
| **Static file scan** | on write/save of your `.ps1`/`.sct`/`.vbs` | Yes — file quarantined before it runs |
| **AMSI (runtime script scan)** | when a script host executes content | Sometimes — suspends/kills the running script |
| **Behavior monitor** | on malicious *actions* (LSASS touch, etc.) | Rarely — usually after EID 1 |
| **Process-creation hard block** | `CreateProcess` on a known-bad cmdline | **Yes — no EID 1 ever** |

> **Key insight:** Sysmon logs **EID 1 at process creation, *before* Defender can kill a flagged process.** So a merely-*flagged* command line still produces your fixture. Only a **hard creation block** (`Start-Process` throws *"Access is denied"*) actually loses the event. Don't over-fix cases that already log.

## 1. Recon — is Defender even on, and what's excluded?
```powershell
Get-MpComputerStatus | Select RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled
Get-MpPreference | Select ExclusionPath,ExclusionProcess,AttackSurfaceReductionRules_Ids   # needs admin
```

## 2. Quick triage — `Get-MpThreatDetection`
```powershell
Get-MpThreatDetection | Sort InitialDetectionTime -Desc |
  Select InitialDetectionTime,
    @{n='Threat';e={(Get-MpThreat -ThreatID $_.ThreatID).ThreatName}},
    @{n='Res';e={($_.Resources) -join '; '}} | Format-Table -Auto -Wrap
```
Read the **`Resources` prefix** — it tells you the layer:

| Prefix | Meaning | Fix direction |
|---|---|---|
| `file:_<path>` / `containerfile:_` | static on-disk scan | **clean the file text** |
| `amsi:_<host.exe>` | runtime script scan | see §2A — it only names the *host*, not the content |
| `CmdLine:_<cmdline>` | command-line detection | inert cmdline / allowed variant |
| `behavior:_process:…` | behavior monitor | make the *action* inert (bad PID, missing file) |

`Get-MpThreatDetection` is the 5-second look. **It stops here** — for `amsi:_`/`file:_` detail, or to find the actual content, use §2A.

---

## 2A. Deep dive — the Defender Operational log (use this for real investigation)

`Get-MpThreatDetection` gives you a threat name and a resource string and nothing else. The **Windows Defender Operational event log** carries the full record. This is *the* command:

```powershell
# Dump every field of the last few detections
Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' |
  Where-Object Id -in 1116,1117 | Select-Object -First 5 | ForEach-Object {
    "`n=== $($_.TimeCreated)  EID $($_.Id) ==="
    ([xml]$_.ToXml()).Event.EventData.Data | ForEach-Object { '{0,-18}: {1}' -f $_.Name, $_.'#text' }
  }
```
`.ToXml()` is the trick — it turns the event's `EventData` into clean `Name : value` pairs instead of the prose `.Message` blob.

**Event IDs:** `1116` = *threat detected*, `1117` = *action taken*. You get them as a **pair** — 1116 first (Action = `Not Applicable`), then 1117 a few seconds later with the real Action (`Quarantine`/`Remove`/`Allow`).

**Fields that matter:**

| Field | How to read it |
|---|---|
| **Threat Name** | e.g. `Trojan:PowerShell/FakeCaptcha.Y!MTB`. Suffix `!MTB` = cloud/ML heuristic → fuzzy, fires on *suspicious-looking* content, not just exact matches. |
| **Path** | the resource — `amsi:_<host>`, `file:_<path>`, `CmdLine:_…`, `containerfile:_…`. Same decoder as §2. |
| **Process Name** | **the key field for `amsi:_` hits** — the process that was *running* the flagged content (your lead on where it came from). |
| **Execution Name** | `Suspended` = AMSI caught it *before* it executed (pre-run). Confirms it's an AMSI pre-scan, not a behavior block. |
| **Detection User** | whose session (`DOMAIN\user`). |
| **Origin Name** | source: `Local`, `Internet`, `Unknown` (AMSI buffers are usually `Unknown`). |
| **Action Name** | on the 1117 event: what Defender did. |

To pull one specific detection, filter by time instead of `-First`:
```powershell
$when = Get-Date '2026-07-15 12:31:57'
Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' |
  Where-Object { $_.Id -in 1116,1117 -and [math]::Abs(($_.TimeCreated-$when).TotalMinutes) -lt 3 } | ...
```

### Getting the actual script content (the part even 1116/1117 won't give you)
The Operational log names the **host process** but still **not the script text** — Defender doesn't keep the scanned buffer. Two ways to recover it:

**(a) Correlate the timestamp with PowerShell Script Block Logging (EID 4104).** When AMSI flags a block, PowerShell logs 4104 with the full `ScriptBlockText`. Query a ±90s window around the Defender timestamp:
```powershell
$when = Get-Date '2026-07-15 12:31:57'
Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' |
  Where-Object { $_.Id -eq 4104 -and [math]::Abs(($_.TimeCreated-$when).TotalSeconds) -lt 90 } |
  ForEach-Object {
    $t = (([xml]$_.ToXml()).Event.EventData.Data | Where-Object Name -eq 'ScriptBlockText').'#text'
    "`n[$($_.TimeCreated)]`n$t"
  }
```
If nothing returns, turn script-block logging on (admin, one-time) and reproduce:
```powershell
$k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
New-Item $k -Force | Out-Null
Set-ItemProperty $k -Name EnableScriptBlockLogging -Type DWord -Value 1
```

**(b) Inspect the host process from `Process Name`.** For `powershell_ise.exe`, ISE auto-saves open/untitled tabs and **re-scans them on every load** — so a stale tab keeps re-triggering. Find the file:
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Microsoft_Corporation\PowerShell_ISE.exe_*" -Recurse -Filter *.ps1 -EA SilentlyContinue |
  Sort LastWriteTime -Desc | Select LastWriteTime,FullName -First 8
```

### When `Process Name` = `powershell.exe` (not ISE) and it recurs — hunt the launcher, not a file
An `amsi:_…powershell.exe` hit with `Source Name = AMSI` and `Execution = Suspended` means **something executed flagged content through Windows PowerShell and AMSI caught it pre-run**. The Operational log names the *host*, not *what launched it*. Pivot to two other logs — and don't fix a file; find the launcher + any persistence:

```powershell
$when = Get-Date '2026-07-15 13:12:43'   # the Defender TimeCreated

# (1) The content — script-block log (4104) at that second
Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' |
  Where-Object { $_.Id -eq 4104 -and [math]::Abs(($_.TimeCreated-$when).TotalSeconds) -lt 60 } |
  ForEach-Object { "`n[$($_.TimeCreated)]"; (([xml]$_.ToXml()).Event.EventData.Data | Where-Object Name -eq 'ScriptBlockText').'#text' }

# (2) The launcher — parent + full cmdline of that powershell.exe (Sysmon EID 1, needs admin; or Security 4688)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=1;StartTime=$when.AddSeconds(-45);EndTime=$when.AddSeconds(45)} |
  ForEach-Object { $h=@{}; ([xml]$_.ToXml()).Event.EventData.Data | ForEach-Object { $h[$_.Name]=$_.'#text' }
    if ($h.Image -like '*powershell.exe') { "{0}`n  Parent: {1} (PID {2})`n  Cmd: {3}" -f $_.TimeCreated,$h.ParentImage,$h.ParentProcessId,$h.CommandLine } }

# (3) Why it recurs — persistence that re-launches PowerShell (usually a leftover ART atomic)
Get-ScheduledTask | ForEach-Object { $s = ($_.Actions.Execute -join ' ') + ' ' + ($_.Actions.Arguments -join ' ')
  if ($s -match 'powershell|mshta|-enc|hidden|iex|FromBase64|AtomicRedTeam') { '{0}\{1}  ->  {2}' -f $_.TaskPath,$_.TaskName,$s.Trim() } }
'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' |
  ForEach-Object { Get-ItemProperty $_ -ErrorAction SilentlyContinue }
```
Run **(2) and (3) first** — they identify the launcher without touching the payload. **Caution:** pulling the flagged `ScriptBlockText` (1) *back through* a powershell.exe session can re-trip AMSI on your own shell, so it can be part of what you see recurring. Cleanup: an Atomic → `Invoke-AtomicTest <technique> -Cleanup`; a run-key/task → delete that entry.

### Worked example — the `FakeCaptcha` hit on `powershell_ise.exe`
- **1116 @ 12:31:57** (Action `Not Applicable`) → **1117 @ 12:33:28** (Action `Quarantine`): detected, then quarantined ~90s later.
- `Path = amsi:_…powershell_ise.exe`, `Process Name = powershell_ise.exe`, `Execution = Suspended` → **ISE loaded a script block that AMSI flagged before it ran.**
- `!MTB` + `FakeCaptcha` (the ClickFix family) → almost certainly a **recovered ISE tab** holding an old ART ClickFix atomic — *not* the telemetry generator (the generator writes payloads to disk and launches via `Start-Process`; it never runs content through ISE's AMSI). **Fix: close/delete the offending ISE tab / autosave file** — nothing to change in the generator.

---

## 3. Confirm a file is clean (single-file on-demand scan)
```powershell
& "C:\Program Files\Windows Defender\MpCmdRun.exe" -Scan -ScanType 3 -File "<path>"
# exit 0 + "found no threats" = clean. Re-run after each edit.
```

## 4. Test if a specific command line is creation-blocked
```powershell
try { $p = Start-Process regsvr32.exe -ArgumentList $args -PassThru -ErrorAction Stop
      "started PID $($p.Id)"; Stop-Process $p.Id -Force }
catch { "BLOCKED: $($_.Exception.Message)" }   # "Access is denied" = hard block, no EID 1
```
Binary-search the args to find *which token* triggers it (drop `scrobj.dll`, swap `/i:http`→`/i:ftp`, etc.).

## 5. Fix patterns (in order of preference)
- **Static hit (`file:_`)** → don't embed a runnable malicious sequence in the file. Build risky tokens from fragments (`'WScript'+'.Shell'`), reference exports by **ordinal** not name, never write a `mshta→powershell→-enc` chain. You only need the *string on EID 1*, not a working attack.
- **Behavior/AMSI hit** → make the trigger **inert**: invalid PID, non-existent DLL/URL, no-op scriptlet body, `vbscript:close` with the signal token as a trailing arg.
- **Hard creation block** → find an **allowed variant that hits the same rule selection** (e.g. `/i:ftp` for `/i:http`). If none exists, document it and rely on a sibling case for that selection.
- **Belt-and-suspenders** → temp `Add-MpPreference -ExclusionPath <labdir>` in `try`, `Remove-MpPreference` in `finally`. Needs admin; **Tamper Protection can silently veto it**; only covers *file* scans in that path — not cmdline/behavior/AMSI.

## Gotchas
- Reading `Microsoft-Windows-Sysmon/Operational` and `wevtutil epl` need **admin** — you can test AV blocks non-elevated, but not the actual EVTX export. (The Defender + PowerShell Operational logs in §2A *are* readable as your own user.)
- `Get-MpThreatDetection` also catches your **own diagnostic `powershell -Command`** text (AMSI on the harness) — don't confuse that with the target file.
- Detections are keyed by threat *name* — the same string can flag as different names across signature updates; go by the **`Path`/`Process Name` layer**, not the name.
- An `amsi:_…powershell_ise.exe` or `…powershell.exe` hit is often a **stale ISE tab / your own test harness**, not the artefact you're building. Check `Process Name` before you touch the generator.
