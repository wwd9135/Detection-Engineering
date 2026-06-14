# Emulation Index

This folder contains test procedures for validating detections in the home lab. Each sub-folder maps to one ATT&CK technique and documents the specific emulation steps, expected telemetry, and links to the detection that should fire.

All tests are run against synthetic lab hosts (see [lab/README.md](../lab/README.md)). No production systems or employer infrastructure involved.

---

## Emulation Tooling

| Tool | Purpose | Notes |
|---|---|---|
| [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) | Technique-level emulations | Primary tool — covers most techniques |
| [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam) | PowerShell runner for ART | Handles setup, execution, and cleanup |
| Manual PowerShell / cmd.exe | Ad-hoc emulation | Where no ART test exists or ART is too broad |

### Setup (Invoke-AtomicRedTeam)

```powershell
# Install Invoke-AtomicRedTeam (run once on the lab host)
Install-Module -Name invoke-atomicredteam, powershell-yaml -Scope CurrentUser

# Import the module
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1"

# Install prerequisite files for a specific test
Invoke-AtomicTest T1547.001 -GetPrereqs

# Run the test
Invoke-AtomicTest T1547.001 -TestNumbers 1

# Clean up after testing
Invoke-AtomicTest T1547.001 -TestNumbers 1 -Cleanup
```

---

## Test Index

| Technique | ATT&CK ID | ART Test | Status | Detection Rule |
|---|---|---|---|---|
| Registry Run Key Persistence | T1547.001 | Test 1 | Validated | [T1547.001-registry-run-keys](../detections/persistence/T1547.001-registry-run-keys/README.md) |
| *(more to come)* | | | | |

---

## General Emulation Process

1. **Snapshot the lab VM** before running any test — restoring to a clean state after each test prevents artefact accumulation.
2. **Start a Sentinel query** before triggering the technique — note the timestamp so you can filter exactly to the test window.
3. **Run the ART test** (or manual equivalent) and note the exact command, timestamp, and PID.
4. **Confirm telemetry** — verify the expected event appeared in the raw log table.
5. **Run the compiled KQL** against the captured telemetry — confirm it returns the expected row.
6. **Document results** in the relevant `validation.md`.
7. **Run cleanup** and restore the VM snapshot.
