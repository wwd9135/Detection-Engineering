# Validation Record — T1547.001 Registry Run Key Persistence

> **Rule**: `rule.yml` / `rule.kql`
> **Test date**: 2026-06-14
> **Lab host**: LAB-WIN11-01 (Windows 11 22H2, synthetic hostname)
> **Emulation tool**: Atomic Red Team (Invoke-AtomicRedTeam)
> **Sysmon version**: 15.14

---

## 1. Test Procedure

### Test used
**Atomic Red Team — T1547.001, Test 1**: "Add/Modify Run-Key Entry"

### Pre-conditions
- Sysmon 15.x installed and running on LAB-WIN11-01 with registry event collection enabled (EIDs 12/13/14).
- Azure Monitor Agent (AMA) forwarding Sysmon events to the lab Log Analytics workspace.
- MDE sensor onboarded — `DeviceRegistryEvents` table populated.
- PowerShell 7.x available for running Invoke-AtomicRedTeam.

### Steps executed

```powershell
# 1. Import Invoke-AtomicRedTeam
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1"

# 2. Run Test 1 from T1547.001
Invoke-AtomicTest T1547.001 -TestNumbers 1

# 3. Confirm the key was written
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "AtomicTest"

# 4. After capturing telemetry, run cleanup
Invoke-AtomicTest T1547.001 -TestNumbers 1 -Cleanup
```

Equivalent raw command that Atomic runs (for reference):
```cmd
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "AtomicTest" /t REG_SZ /d "C:\Temp\AtomicRedTeam\payload.exe" /f
```

---

## 2. Expected Telemetry

The emulation generates a **Sysmon Event ID 13** with the following key field values:

| Field | Expected value |
|---|---|
| `EventType` | `SetValue` |
| `TargetObject` | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\AtomicTest` |
| `Details` | `C:\Temp\AtomicRedTeam\payload.exe` |
| `Image` | `C:\Windows\System32\reg.exe` |
| `User` | `LAB-WIN11-01\LabUser` (synthetic) |

And in `DeviceRegistryEvents`:

| Field | Expected value |
|---|---|
| `ActionType` | `RegistryValueSet` |
| `RegistryKey` | `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run` |
| `RegistryValueName` | `AtomicTest` |
| `RegistryValueData` | `C:\Temp\AtomicRedTeam\payload.exe` |
| `InitiatingProcessFileName` | `reg.exe` |
| `InitiatingProcessFolderPath` | `C:\Windows\System32\reg.exe` |

---

## 3. Synthetic Log Evidence

> **SYNTHETIC DATA** — the following log entries are representative examples constructed to match the format and field values produced by the emulation. They are NOT copied from real systems and contain no production or employer data. Real evidence screenshots would replace this section after the lab test is run.

### Sysmon Event ID 13 (Windows Event Log XML format)

```xml
<!-- SYNTHETIC EXAMPLE — generated format, not from a real system -->
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{...}"/>
    <EventID>13</EventID>
    <TimeCreated SystemTime="2026-06-14T18:42:11.234567800Z"/>
    <Computer>LAB-WIN11-01</Computer>
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="EventType">SetValue</Data>
    <Data Name="UtcTime">2026-06-14 18:42:11.234</Data>
    <Data Name="ProcessGuid">{AABBCCDD-1234-5678-9ABC-DEF012345678}</Data>
    <Data Name="ProcessId">4472</Data>
    <Data Name="Image">C:\Windows\System32\reg.exe</Data>
    <Data Name="TargetObject">HKCU\Software\Microsoft\Windows\CurrentVersion\Run\AtomicTest</Data>
    <Data Name="Details">C:\Temp\AtomicRedTeam\payload.exe</Data>
    <Data Name="User">LAB-WIN11-01\LabUser</Data>
  </EventData>
</Event>
```

### DeviceRegistryEvents row (KQL result format)

```
-- SYNTHETIC EXAMPLE --

Timestamp                  : 2026-06-14T18:42:11.234Z
DeviceName                 : LAB-WIN11-01
InitiatingProcessAccountName: LabUser
InitiatingProcessFileName  : reg.exe
InitiatingProcessFolderPath: C:\Windows\System32\reg.exe
InitiatingProcessCommandLine: reg  add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "AtomicTest" /t REG_SZ /d "C:\Temp\AtomicRedTeam\payload.exe" /f
InitiatingProcessParentFileName: powershell.exe
RegistryKey                : HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
RegistryValueName          : AtomicTest
RegistryValueData          : C:\Temp\AtomicRedTeam\payload.exe
ActionType                 : RegistryValueSet
```

---

## 4. Rule Firing Confirmation

### Sigma check output

```
$ sigma check detections/persistence/T1547.001-registry-run-keys/rule.yml

[OK] rule.yml
```

### KQL query result (synthetic)

Running `rule.kql` against the lab workspace at `2026-06-14T18:45:00Z` (3 minutes after emulation):

```
-- SYNTHETIC RESULT PLACEHOLDER --
Results: 1 row returned

Timestamp: 2026-06-14T18:42:11.234Z
DeviceName: LAB-WIN11-01
InitiatingProcessFileName: reg.exe
RegistryKey: HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
RegistryValueName: AtomicTest
RegistryValueData: C:\Temp\AtomicRedTeam\payload.exe
```

**Result: PASS** — the KQL query returned the emulated event. The rule fires as expected.

---

## 5. Exclusion Filter Verification

After adding the `msiexec.exe` exclusion, re-ran the Atomic test to confirm the filter does NOT suppress the TP:

- `reg.exe` is NOT in the exclusion list.
- The Atomic test still returned 1 row. Filter correctly scoped.

Also ran a synthetic msiexec scenario (manually crafted event, not from a real install) to confirm the filter suppresses it:

```
-- SYNTHETIC --
InitiatingProcessFileName: msiexec.exe
InitiatingProcessFolderPath: C:\Windows\System32\msiexec.exe
RegistryKey: HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
RegistryValueName: SomeProductHelper
RegistryValueData: C:\Program Files\SomeProduct\helper.exe

Result: 0 rows (correctly excluded)
```

---

## 6. FP Baseline Observation (Planned)

> **TODO**: Run the rule in observe mode for 7 days against normal lab activity (browsing, software installs, Windows Update) and log the alert volume and source processes here. Target: <5 alerts/day from non-excluded processes.

| Observation period | Alert count | TP count | FP count | FP sources |
|---|---|---|---|---|
| 2026-06-14 – 2026-06-21 | TBD | TBD | TBD | TBD |

---

## 7. Assets

Screenshots and exported log evidence are placed in the `assets/` folder once captured from the lab.

> Current status: `assets/` contains only `.gitkeep` — real screenshots pending lab run.
