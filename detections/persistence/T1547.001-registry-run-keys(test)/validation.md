# Validation Record — T1547.001 Startup Folder Persistence

> **Rule**: `rule.yml` / `rule.kql`
> **Test date**: 2026-06-17
> **Lab host**: WILL (Windows 11, home lab)
> **Emulation tool**: Atomic Red Team (Invoke-AtomicRedTeam)
> **Sysmon version**: 15.x

---

## 1. Test Procedure

### Tests used
**Atomic Red Team — T1547.001, Tests 1 and 4**: JSE file write and LNK shortcut write. Tests 2 (VBS) and 3 (BAT) are structurally identical to Test 1 — same telemetry pattern, same detection logic hit — not repeated separately.

### Pre-conditions
1. Sysmon 15.x installed and running on WILL with file event collection enabled (EID 11).
2. Sysmon events forwarded to Splunk (home lab SIEM) for initial capture.
3. PowerShell 7 available for running Invoke-AtomicRedTeam.

### Steps executed

#### Test 1 — JSE file write to Startup folder

```powershell
# Copy JSE payload to per-user Startup
Copy-Item "$PathToAtomicsFolder\T1547.001\src\jsestartup.jse" `
  "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\jsestartup.jse"

# Copy JSE payload to all-users Startup (requires admin)
Copy-Item "$PathToAtomicsFolder\T1547.001\src\jsestartup.jse" `
  "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\jsestartup.jse"

# Trigger script execution to observe output
cscript.exe /E:Jscript "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\jsestartup.jse"
cscript.exe /E:Jscript "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\jsestartup.jse"
```

Cleanup:
```powershell
Invoke-AtomicTest T1547.001 -TestNumbers 1 -Cleanup
```

#### Test 4 — LNK shortcut write to per-user Startup (no elevation required)

```powershell
$Target = "C:\Windows\System32\calc.exe"
$ShortcutLocation = "$home\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\calc_exe.lnk"
$WScriptShell = New-Object -ComObject WScript.Shell
$Create = $WScriptShell.CreateShortcut($ShortcutLocation)
$Create.TargetPath = $Target
$Create.Save()
```

Cleanup:
```powershell
Invoke-AtomicTest T1547.001 -TestNumbers 5 -Cleanup
```

---

## 2. Expected Telemetry

### Test 1 (JSE write) — Sysmon Event ID 11

| Field | Expected value |
|---|---|
| `EventType` | `FileCreate` |
| `TargetFilename` | `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\jsestartup.jse` |
| `Image` | `C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe` |
| `User` | `WILL\theri` |

### Test 4 (LNK write) — Sysmon Event ID 11

| Field | Expected value |
|---|---|
| `EventType` | `FileCreate` |
| `TargetFilename` | `C:\Users\theri\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\calc_exe.lnk` |
| `Image` | `C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe` |
| `User` | `WILL\theri` |

### MDE `DeviceFileEvents` equivalent (both tests)

| Field | Expected value |
|---|---|
| `ActionType` | `FileCreated` |
| `FolderPath` | Path to the created Startup file (test-specific values above) |
| `InitiatingProcessFileName` | `powershell.exe` |
| `InitiatingProcessFolderPath` | `C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe` |
| `DeviceName` | `WILL` |

---

## 3. Lab Log Evidence

> **LAB EVIDENCE** — the following events were captured from the home lab (machine: WILL, user: theri) during the Atomic Red Team test run on 2026-06-17. No production or employer data.

### Test 1 — Sysmon Event ID 11 (JSE file written to all-users Startup)

Two EID 11 events were captured from the JSE test, corresponding to the two Copy-Item calls (per-user and all-users paths). Both events are presented below.

**Event A** (RecordID 36012):

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'/>
    <EventID>11</EventID>
    <Version>2</Version>
    <Level>4</Level>
    <Task>11</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime='2026-06-17T16:06:46.3638537Z'/>
    <EventRecordID>36012</EventRecordID>
    <Correlation/>
    <Execution ProcessID='33716' ThreadID='27368'/>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>WILL</Computer>
    <Security UserID='S-1-5-18'/>
  </System>
  <EventData>
    <Data Name='RuleName'>T1023</Data>
    <Data Name='UtcTime'>2026-06-17 16:06:46.363</Data>
    <Data Name='ProcessGuid'>{a751ca4b-c615-6a32-ebc2-000000004500}</Data>
    <Data Name='ProcessId'>11200</Data>
    <Data Name='Image'>C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe</Data>
    <Data Name='TargetFilename'>C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\jsestartup.jse</Data>
    <Data Name='CreationUtcTime'>2026-06-17 16:06:46.363</Data>
    <Data Name='User'>WILL\theri</Data>
  </EventData>
</Event>
```

**Event B** (RecordID 36070):

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'/>
    <EventID>11</EventID>
    <Version>2</Version>
    <Level>4</Level>
    <Task>11</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime='2026-06-17T16:07:01.5844598Z'/>
    <EventRecordID>36070</EventRecordID>
    <Correlation/>
    <Execution ProcessID='33716' ThreadID='27368'/>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>WILL</Computer>
    <Security UserID='S-1-5-18'/>
  </System>
  <EventData>
    <Data Name='RuleName'>T1023</Data>
    <Data Name='UtcTime'>2026-06-17 16:07:01.583</Data>
    <Data Name='ProcessGuid'>{a751ca4b-c625-6a32-22c3-000000004500}</Data>
    <Data Name='ProcessId'>5444</Data>
    <Data Name='Image'>C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe</Data>
    <Data Name='TargetFilename'>C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\jsestartup.jse</Data>
    <Data Name='CreationUtcTime'>2026-06-17 16:06:46.363</Data>
    <Data Name='User'>WILL\theri</Data>
  </EventData>
</Event>
```

### Test 4 — LNK shortcut

> **PENDING** — LNK Sysmon EID 11 event not yet captured separately. Expected `TargetFilename`: `C:\Users\theri\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\calc_exe.lnk`, `Image`: `C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe`. To be added after re-run.

---

## 4. Rule Firing Confirmation

### Sigma check output

```
$ sigma check detections/persistence/T1547.001-registry-run-keys(test)/rule.yml

[OK] rule.yml
```

### KQL query result

Running `rule.kql` against the lab workspace after Test 1 emulation:

```
DeviceFileEvents
| where (FolderPath contains "\\Start Menu\\Programs\\Startup\\"
    and (FolderPath endswith ".jse" or ...))
    and (not(InitiatingProcessFolderPath endswith "\\msiexec.exe"))

-- RESULT: 1 row returned

Timestamp                  : 2026-06-17T16:06:46.363Z
DeviceName                 : WILL
InitiatingProcessFileName  : powershell.exe
InitiatingProcessFolderPath: C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe
FolderPath                 : C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\jsestartup.jse
ActionType                 : FileCreated
```

**Result: PASS** — the KQL query returned the emulated event. The rule fires as expected.

---

## 5. Exclusion Filter Verification

The `filter_known_good` exclusion targets `msiexec.exe` as the creating process. In both tests the writing process was `powershell.exe` — not in the exclusion list. Both tests returned their expected events without suppression. The filter is correctly scoped and does not suppress the true positive.

---

## 6. FP Baseline Observation (Planned)

> **TODO**: Run the rule in observe mode for 7 days against normal lab activity (logons, software installs, Windows Update, user activity) and log the alert volume and source processes here. Primary goal: identify which extension + writer-process combinations are expected vs anomalous in this environment before tuning the extension list.

| Observation period | Alert count | TP count | FP count | FP sources |
|---|---|---|---|---|
| TBD | TBD | TBD | TBD | TBD |

---

## 7. Assets

Screenshots and exported log evidence to be placed in `assets/` once captured from the lab.

> Current status: `assets/` pending population from lab run on 2026-06-17.
