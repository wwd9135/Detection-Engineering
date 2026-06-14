# Tuning: Reduce FP Volume on Run-Key Detection from Software Installers

> **Date**: 2026-06-14
> **Rule**: [Windows Registry Run Key Persistence via Sysmon](../../detections/persistence/T1547.001-registry-run-keys/README.md)
> **Author**: William Richardson

---

## Rule / Target

| Field | Value |
|---|---|
| Rule file | `detections/persistence/T1547.001-registry-run-keys/rule.yml` |
| Sigma rule ID | `a7f3c2e1-84b6-4d2a-9f1e-3c8b5a6d7e90` |
| Deployed in | Microsoft Sentinel (lab workspace) |
| Observation period | 2026-06-14 – 2026-06-14 (synthetic baseline estimate) |

---

## Problem Statement

Initial version of the rule had no exclusions — any write to a Run/RunOnce key path fired an alert. During baseline observation in the lab, the Windows Installer service (`msiexec.exe`) generated run-key writes as part of installing software with auto-update agents (e.g., Microsoft Office Click-to-Run, Visual Studio Code).

In a lab with a single user actively installing software, this produced approximately 10–15 FP alerts per software installation session. In a real enterprise environment this volume would be much higher. The FP rate made the rule impractical to operate as a real-time alert.

---

## Hypothesis

The majority of noise originates from `msiexec.exe`. Windows Installer is the standard mechanism for package-based software deployment, and its run-key writes are well-understood. Adding a filter on `msiexec.exe` should reduce the FP rate substantially.

Adversary payloads almost never execute through `msiexec.exe` to write a run key (they would more commonly use `cmd.exe`, `powershell.exe`, `reg.exe`, or a custom payload binary). So the filter should not create a meaningful blind spot for the targeted adversary behaviour.

---

## Before Logic

```yaml
detection:
  selection:
    EventType: SetValue
    TargetObject|contains:
      - '\Software\Microsoft\Windows\CurrentVersion\Run\'
      - '\Software\Microsoft\Windows\CurrentVersion\RunOnce\'
      - '\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run\'
      - '\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce\'
  condition: selection
```

**Before metrics (lab synthetic estimate):**

| Metric | Value |
|---|---|
| Alert volume (single install session) | ~12 alerts |
| Confirmed TPs | 0 (no adversary activity) |
| Confirmed FPs | 12 (all msiexec from VS Code install) |
| FP rate | ~100% (install sessions) |

---

## After Logic

```yaml
detection:
  selection:
    EventType: SetValue
    TargetObject|contains:
      - '\Software\Microsoft\Windows\CurrentVersion\Run\'
      - '\Software\Microsoft\Windows\CurrentVersion\RunOnce\'
      - '\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run\'
      - '\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce\'
  filter_system_processes:
    Image|startswith:
      - 'C:\Windows\System32\msiexec.exe'
      - 'C:\Windows\SysWOW64\msiexec.exe'
  filter_empty_value:
    Details: ''
  condition: selection and not 1 of filter_*
```

**After metrics (same install session replayed):**

| Metric | Value |
|---|---|
| Alert volume (single install session) | 0 alerts |
| Confirmed TPs | 0 |
| Confirmed FPs | 0 |
| FP rate | 0% (during install-only sessions) |

---

## What Changed and Why

1. **`filter_system_processes`** — added `Image|startswith` filter for both the 32-bit and 64-bit `msiexec.exe` paths. Path-anchored to the system directory to prevent an adversary placing a fake `msiexec.exe` elsewhere from benefiting from the exclusion.

2. **`filter_empty_value`** — added `Details: ''` filter to drop events where the value data is empty. These appear when certain registry operations log a set-value event with no data, which cannot represent a persistence payload.

3. **Condition** — changed from `selection` to `selection and not 1 of filter_*` using the standard Sigma negative-filter pattern.

**What was NOT changed**: The key path list was not narrowed. The goal is to keep the detection broad enough to catch all Run/RunOnce writes, not just common ones. FP reduction is done through process filtering, not key-path scoping.

---

## Validation

- [x] Re-ran Atomic Red Team T1547.001 Test 1 after applying filters — rule still fired (`reg.exe` is not in the exclusion list).
- [x] `reg.exe` and `powershell.exe` (common adversary-used writers) are confirmed NOT excluded.
- [x] `msiexec.exe` writes confirmed excluded.
- [ ] 7-day observe period across normal activity pending (lab activity baseline still being collected).

---

## Outstanding Issues / Next Steps

- Browser auto-update agents (Chrome, Firefox) sometimes use their own per-app updater binaries to write run keys. These originate from user-writable paths like `%APPDATA%\Local\Google\Update\` and are harder to filter safely. Next tuning pass will address these if volume warrants it.
- A future improvement: add a `SignatureStatus` check (MDE field) to filter signed-binary writers while keeping unsigned writers always-alert. Not available in the Sysmon pipeline.

---

## Date

2026-06-14
