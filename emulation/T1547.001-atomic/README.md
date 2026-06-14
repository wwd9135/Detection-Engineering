# Emulation: T1547.001 — Registry Run Key Persistence

> **Atomic Red Team tests**: T1547.001 Test 1, Test 2
> **Detection validated**: [T1547.001-registry-run-keys](../../detections/persistence/T1547.001-registry-run-keys/README.md)
> **Lab host**: LAB-WIN11-01 (synthetic hostname — Windows 11 22H2)

---

## Test 1: Add Run Key via reg.exe (HKCU)

### What it simulates
An adversary with standard user access writes a run-key entry in the current user's hive (`HKCU`). This is the lowest-privilege persistence mechanism — no elevation needed.

### Command
```cmd
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "AtomicTest" /t REG_SZ /d "C:\Temp\AtomicRedTeam\payload.exe" /f
```

### Run with Invoke-AtomicRedTeam
```powershell
Invoke-AtomicTest T1547.001 -TestNumbers 1
```

### Expected Sysmon telemetry
- **Event ID**: 13 (RegistryEvent — Value Set)
- **EventType**: `SetValue`
- **Image**: `C:\Windows\System32\reg.exe`
- **TargetObject**: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\AtomicTest`
- **Details**: `C:\Temp\AtomicRedTeam\payload.exe`

### Expected MDE telemetry
- **Table**: `DeviceRegistryEvents`
- **ActionType**: `RegistryValueSet`
- **RegistryKey**: `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
- **RegistryValueName**: `AtomicTest`
- **RegistryValueData**: `C:\Temp\AtomicRedTeam\payload.exe`
- **InitiatingProcessFileName**: `reg.exe`

### Cleanup
```powershell
Invoke-AtomicTest T1547.001 -TestNumbers 1 -Cleanup
# OR manually:
reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "AtomicTest" /f
```

### Detection result
Rule fires. See [validation.md](../../detections/persistence/T1547.001-registry-run-keys/validation.md) §4.

---

## Test 2: Add RunOnce Key via reg.exe (HKCU)

### What it simulates
Same as Test 1 but targets `RunOnce` — the value is only executed once, then deleted by Windows. Sometimes used by malware droppers during the final stage of a multi-stage infection.

### Command
```cmd
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v "AtomicTest" /t REG_SZ /d "C:\Temp\AtomicRedTeam\payload.exe" /f
```

### Run with Invoke-AtomicRedTeam
```powershell
Invoke-AtomicTest T1547.001 -TestNumbers 2
```

### Expected telemetry
Same as Test 1 with `RunOnce` in the key path.

### Detection result
Rule fires (RunOnce paths are explicitly covered by the rule). Expected.

---

## Test 3 (Manual): PowerShell-based Run Key Write

Not an Atomic test — manual emulation to validate that a different calling process also fires the rule.

### Command
```powershell
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
    -Name "PSAtomicTest" `
    -Value "C:\Temp\payload.exe" `
    -PropertyType String `
    -Force
```

### Expected telemetry
Same fields as Test 1, but `Image` will be `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` or the PowerShell 7 path. `powershell.exe` is NOT in the exclusion list — rule should fire.

### Cleanup
```powershell
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "PSAtomicTest"
```

### Detection result
Expected: rule fires. (Pending lab execution.)

---

## Notes on Timing

Registry events via Sysmon typically appear in Sentinel within 2–5 minutes of the write via the Azure Monitor Agent pipeline. Allow at least 5 minutes after the emulation before querying.

MDE `DeviceRegistryEvents` events typically appear within 1–3 minutes.

---

## Pre-test Checklist

- [ ] VM snapshot taken (clean baseline)
- [ ] Sysmon service confirmed running: `Get-Service -Name Sysmon`
- [ ] AMA agent confirmed running: `Get-Service -Name AzureMonitorAgent`
- [ ] Note start timestamp before running test
- [ ] Sentinel / MDE hunting query open and ready with time filter
