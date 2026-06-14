# Research Notes — T1547.001 Registry Run Key Persistence

*Working notes compiled during rule development. Not polished — this is the actual research trail.*

---

## Starting Point

**Hypothesis**: If an adversary establishes persistence via a registry Run key, Sysmon EID 13 should capture the write. A rule watching for writes to `\CurrentVersion\Run*` should catch a wide range of implementations.

**Why this technique first?**
- High prevalence across commodity and nation-state malware alike.
- Low barrier to entry for the attacker (HKCU writes require no elevation).
- Good telemetry coverage via Sysmon + MDE — this is a data source I know is reliable.
- Atomic Red Team has a clean, simple test I can run immediately.

---

## ATT&CK Page Notes

Pulled from [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/) on 2026-06-14.

**Key takeaways:**

- Technique covers Run keys AND Startup folder — I'm splitting into two separate rules (this one is registry only).
- ATT&CK lists four main key paths:
  - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
  - `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
  - `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
  - `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- Also notes: `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon` (Userinit / Shell values) — separate, more privilege-intensive variant; not covered here.
- Procedure examples mention: Emotet, TrickBot, Cobalt Strike, Lazarus Group, many RATs.
- Detection guidance: "Monitor Registry for changes to run keys."

**WOW6432Node addendum**: 32-bit processes on 64-bit Windows are transparently redirected to `HKLM\Software\WOW6432Node\...`. Sysmon's `TargetObject` records the *effective* redirected path. I should cover WOW6432Node paths explicitly since the Sigma field mapping behaviour across backends varies.

---

## Existing Community Rules Reviewed

Reviewed for field usage and logic patterns — wrote my own rule from scratch.

| Source | Rule name | Notes |
|---|---|---|
| SigmaHQ | `registry_set_persistence_run_key.yml` | Covers same key paths; uses `filter_legitimate_software` with a broader exclusion list. My rule keeps exclusions minimal — I'd rather tune per-environment. |
| Elastic | `persistence_via_run_once_key.toml` | EQL-based; covers `RunOnce` only. Interesting approach to scope-limiting noise. |
| Microsoft Sentinel OOTB | "Suspicious Registry Modification" | Broader scope — covers many registry paths. Noisy. Not pulling from there. |

**Decision**: Write my own Sigma rule. Community rules either have broader scope (more noise) or more aggressive exclusion lists (more blind spots). I want to start minimal and tune from data.

---

## Data Source Research

**Sysmon Event ID 13 — RegistryEvent (Value Set)**

Fields I care about:
- `TargetObject` — full path including value name, e.g. `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\UpdateAgent`
- `EventType` — always `SetValue` for EID 13
- `Image` — the process making the write (this is what I'll filter on)
- `Details` — the value data (the payload path the adversary controls)
- `ProcessId`, `User`, `RuleName`

**MDE DeviceRegistryEvents**

Equivalent fields:
- `RegistryKey` — key path (without value name)
- `RegistryValueName` — value name (separated from key)
- `RegistryValueData` — data written
- `InitiatingProcessFileName`, `InitiatingProcessFolderPath`, `InitiatingProcessCommandLine`

**Observation**: Sigma's `registry_set` category maps `TargetObject` to the key+value concatenated (Sysmon style). The microsoft_xdr pySigma pipeline handles the split between `RegistryKey` and `RegistryValueName` automatically. Good — I don't need to handle this manually.

---

## Atomic Red Team Test Reviewed

[T1547.001 — Atomic Red Team](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md)

**Test 1 — Add/Modify Run-Key Entry** (the one I'll use):
```powershell
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "AtomicTest" /t REG_SZ /d "C:\Temp\AtomicRedTeam\payload.exe" /f
```
- Cleanup: `reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "AtomicTest" /f`
- Writes to HKCU — no elevation required, good baseline test.
- Process making the write is `reg.exe` (from `C:\Windows\System32\`) — this process is NOT in my exclusion list, so it should fire the rule. Confirmed.

**Test 2 — Add/Modify RunOnce**:
```powershell
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v "AtomicTest" /t REG_SZ /d "C:\Temp\AtomicRedTeam\payload.exe" /f
```
- Covers the RunOnce path.

---

## Potential Evasion Paths (noted for blind spots section)

1. **Offline hive edit** — mount NTUSER.DAT, edit with a registry editor that writes directly to the file. No API call, no Sysmon event. Would require physical/privileged access or bootkit.
2. **Registry symlinks** — create a registry symbolic link to redirect writes through an alternate key. Exotic, rarely seen in the wild.
3. **Direct syscall bypass** — bypass the Windows API (`NtSetValueKey` directly) in a way that avoids Sysmon's kernel callback. Kernel-mode capability, not common in commodity malware.
4. **Other autostart key variants** — `RunServices`, `RunServicesOnce`, `RunOnceEx`, `Winlogon` key values (Userinit, Shell). All documented on ATT&CK page but less common.

---

## Field Mapping Verification

Ran a quick check of the pySigma `microsoft_xdr` pipeline field mappings to confirm:

- `EventType: SetValue` → `ActionType == "RegistryValueSet"` ✓
- `TargetObject` → `RegistryKey` + `RegistryValueName` (concatenated in query) ✓
- `Image` → `InitiatingProcessFolderPath` ✓

KQL output reviewed manually — see `rule.kql`.

---

## Open Questions

- [ ] Should I add `\Software\Microsoft\Windows NT\CurrentVersion\Winlogon` as a separate rule or extend this one? Lean toward separate — different technique nuance and different FP profile.
- [ ] How common is `RunOnceEx` in the lab baseline? Need to observe for a week before deciding if it needs its own filter.
- [ ] WOW6432Node: confirm pySigma microsoft_xdr backend handles the contains match correctly for both 32-bit and 64-bit process paths. Need to test with a 32-bit reg.exe emulation.
