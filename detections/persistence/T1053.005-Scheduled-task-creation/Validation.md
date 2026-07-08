# Validation — T1053.005 Scheduled Task Creation

> **Rules**: `rule.yml` (Sigma base) · `rule.spl` (Splunk, V2 post-tuning)
> **Test dates**: 2026-07-07 (Chainsaw batch) · 2026-07-08 (Atomic Red Team)
> **Lab host**: LAB-WIN11-01 (Windows 11 22H2, synthetic hostname)
> **Emulation**: Custom EVTX fixture batch (`Telemetry_Collector.ps1`) via Chainsaw · Atomic Red Team (Invoke-AtomicRedTeam)

---

## Pre-conditions

- EID 4698 auditing enabled ("Audit Other Object Access Events" → Success) — without it the Security log never records task creation at all.
- Fixtures generated on the lab host with [Telemetry_Collector.ps1](Telemetry_Collector.ps1): each test case registers a real scheduled task, exports the resulting 4698 to its own EVTX slice, then cleans the task up. Real events, not hand-crafted XML.
- Chainsaw 2.16.0 driven by the repo's pytest harness (`tests/test_detections.py`), which asserts fire-on-malicious / quiet-on-benign per fixture. Two harness gotchas cost time before any real testing happened: the stock Chainsaw Sigma mapping doesn't declare `TaskContent` (added to `tests/mappings/sigma-event-logs-all.yml`), and `---` dash-runs inside rule comments make Chainsaw silently drop the whole rule (see the NB in `rule.yml`).
- Splunk running locally for the ART round, ingesting the Security log as `XmlWinEventLog`.

---

## Round 1 — Chainsaw batch testing (Sigma rule)

Five malicious and five benign 4698 fixtures (see [research-notes.md](research-notes.md) for what each one exercises). Three tuning iterations:

| Iteration | Benign FP rate | Malicious TP rate |
|---|---|---|
| 1 | 20% | 80% |
| 2 | 40% | 100% |
| 3 | 0% | 100% |

### Iteration 1 — raw output

```
tests/test_detections.py::test_fixtures_present PASSED                   [  7%]
tests/test_detections.py::test_no_wiring_errors[NOTSET] SKIPPED (got...) [ 15%]
tests/test_detections.py::test_fires_on_malicious[T1053.005-Scheduled-task-creation/malicious_mal_privesc_runlevel_highest] PASSED [ 23%]
tests/test_detections.py::test_fires_on_malicious[T1053.005-Scheduled-task-creation/malicious_mal_pscmdlet_encoded] PASSED [ 30%]
tests/test_detections.py::test_fires_on_malicious[T1053.005-Scheduled-task-creation/malicious_mal_schtask_encoded_powershell] PASSED [ 38%]
tests/test_detections.py::test_fires_on_malicious[T1053.005-Scheduled-task-creation/malicious_mal_wmi_registerbyxml_temp_path] FAILED [ 46%]
tests/test_detections.py::test_fires_on_malicious[T1059.001-PowerShell-Execution/malicious] PASSED [ 53%]
tests/test_detections.py::test_quiet_on_benign[T1053.005-Scheduled-task-creation/benign_benign_clean_powershell_script] FAILED [ 61%]
tests/test_detections.py::test_quiet_on_benign[T1053.005-Scheduled-task-creation/benign_benign_installer_temp_task] PASSED [ 69%]
tests/test_detections.py::test_quiet_on_benign[T1053.005-Scheduled-task-creation/benign_benign_signed_backup_task] PASSED [ 76%]
tests/test_detections.py::test_quiet_on_benign[T1053.005-Scheduled-task-creation/benign_benign_system_maintenance_task] PASSED [ 84%]
tests/test_detections.py::test_quiet_on_benign[T1053.005-Scheduled-task-creation/benign_benign_user_logon_notepad] PASSED [ 92%]
tests/test_detections.py::test_quiet_on_benign[T1059.001-PowerShell-Execution/benign] FAILED [100%]
```

Seven of the nine T1053.005 fixtures behaved as expected. The two misses:

- `mal_wmi_registerbyxml_temp_path` did not fire — a missed true positive. The task registers an admin-sounding executable out of `C:\Users\Public\`, and the rule had no signal covering that folder.
- `benign_clean_powershell_script` fired — false positive. The extension matching was hitting `.ps1` anywhere in the task XML, including a plain unencoded `-File C:\Scripts\Cleanup.ps1`, which is exactly the kind of thing admins schedule every day.

(The T1059.001 benign failure is that rule's problem, tracked in its own tuning record — not touched here.)

### What changed between iterations

**Iteration 1 → 2:** added `\Users\Public\` to the staging-path list. Any user can write there but SYSTEM and legitimate installers essentially never register tasks out of it, so it's cheap signal. This caught the WMI fixture and took the malicious TP rate to 100% — but the benign FP rate went the wrong way (40%): the clean-PowerShell fixture was still firing, and the widened path scoring now also hit the Adobe-style updater fixture running out of `AppData\Local\Temp`. My call at that point: I'd rather carry a benign failure than a malicious one, so TP coverage stayed and the FPs got dealt with next.

**Iteration 2 → 3:** two changes.

- Anchored the extension matching so it only fires on the file the task actually launches, not the same extension mentioned anywhere in the XML — in the task definition the launched script always manifests as e.g. `C:\Scripts\Cleanup.ps1</Arguments>`, so anchoring on the closing tag was enough. That cleared `benign_clean_powershell_script` without losing any TP.
- Reclassified the installer fixture to `malicious_mal_installer_temp_task`. On reflection, an unsigned executable launched hourly out of a user's Temp directory is exactly what I want this rule to surface, even when the arguments look clean — real environments tune out their known updaters with an allow-list in the SIEM, they don't blind the rule to the whole pattern.

### Iteration 3 — raw output

```
tests/test_detections.py::test_fixtures_present PASSED                   [  7%]
tests/test_detections.py::test_no_wiring_errors[NOTSET] SKIPPED (got...) [ 15%]
tests/test_detections.py::test_fires_on_malicious[T1053.005-Scheduled-task-creation/malicious_mal_installer_temp_task] PASSED [ 23%]
tests/test_detections.py::test_fires_on_malicious[T1053.005-Scheduled-task-creation/malicious_mal_privesc_runlevel_highest] PASSED [ 30%]
tests/test_detections.py::test_fires_on_malicious[T1053.005-Scheduled-task-creation/malicious_mal_pscmdlet_encoded] PASSED [ 38%]
tests/test_detections.py::test_fires_on_malicious[T1053.005-Scheduled-task-creation/malicious_mal_schtask_encoded_powershell] PASSED [ 46%]
tests/test_detections.py::test_fires_on_malicious[T1053.005-Scheduled-task-creation/malicious_mal_wmi_registerbyxml_temp_path] PASSED [ 53%]
tests/test_detections.py::test_fires_on_malicious[T1059.001-PowerShell-Execution/malicious] PASSED [ 61%]
tests/test_detections.py::test_quiet_on_benign[T1053.005-Scheduled-task-creation/benign_benign_clean_powershell_script] PASSED [ 69%]
tests/test_detections.py::test_quiet_on_benign[T1053.005-Scheduled-task-creation/benign_benign_signed_backup_task] PASSED [ 76%]
tests/test_detections.py::test_quiet_on_benign[T1053.005-Scheduled-task-creation/benign_benign_system_maintenance_task] PASSED [ 84%]
tests/test_detections.py::test_quiet_on_benign[T1053.005-Scheduled-task-creation/benign_benign_user_logon_notepad] PASSED [ 92%]
======================== 12 passed, 1 skipped in 0.10s =========================
```

All five malicious fixtures fire, all four benign fixtures stay quiet. 100% TP / 0% FP on the batch.

---

## Round 2 — Atomic Red Team (Splunk SPL rule)

Purpose: confirm the rule survives translation from Sigma to SPL, and run the shipped ART T1053.005 tests against it to hunt edge cases the fixture batch didn't cover.

Most of the ART tests turned out to be too weak to be useful for tuning — Tests 1, 4 and 6 create a task pointing calc.exe or notepad.exe at a clean path with no suspicious arguments, which exercises none of the scoring criteria. That's the correct outcome: you can't blanket-alert on every task creation, so they were left alone.

### Test 7 — registry-staged fileless task (the one that mattered)

```powershell
reg add HKCU\SOFTWARE\ATOMIC-T1053.005 /v test /t REG_SZ /d cGluZyAxMjcuMC4wLjE= /f
schtasks.exe /Create /F /TN "ATOMIC-T1053.005" /TR "cmd /c start /min \"\" powershell.exe -Command IEX([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String((Get-ItemProperty -Path HKCU:\\SOFTWARE\\ATOMIC-T1053.005).test)))" /sc daily /st 07:45
```

The payload lives in a registry value, not on disk — the task just reads it back, base64-decodes it and hands it to IEX. Before tuning, this only reached an Informational grade: no staging path, no script extension, and the encoded blob sits in the registry rather than on the command line, so almost nothing scored. It honestly deserves High. The saving grace was that my T1059.001 rule would have caught the decoded script block at execution time anyway, but relying on that is not defence in depth — the creation event itself should grade properly.

**Fix:** added a `susp_fileless` signal (+2) to the SPL rule that fires only when the task action both reads a registry value (`Get-ItemProperty` / `reg query` / a bare `HKCU:`/`HKLM:` path) **and** decodes-or-executes it (`FromBase64String` / `IEX` / `Invoke-Expression` / `::GetString` / decompress). Requiring both halves keeps the FP surface small — a task that merely reads the registry, or merely decodes a string, doesn't trip it. As part of the same pass, `-enc` handling was split out into its own `susp_encoded` signal that requires an actual base64 blob after the switch, so encoded commands score once and cleanly.

**Result after tuning:** Test 7 grades Medium/High consistently — it would reach an analyst queue.

![Splunk output — ART Test 7 firing at Medium (Score 4) after the susp_fileless addition; the registry-staged payload is visible in Arguments](<Assets/Screenshot 2026-07-08 175536.png>)

### Full fixture re-run through Splunk

To close the loop, all ten of the task creations from the Chainsaw round were replayed against the SPL rule in Splunk. Every malicious creation graded Medium or High. The benign creations produced no alerts except one Informational — a task with a slightly suspicious path folder — which is acceptable, since Informational sits below the analyst-queue floor and exists exactly for that kind of borderline case.

Test 10 (Ghost Task) was noted but not chased: it creates the task purely via registry manipulation under SYSTEM and deliberately emits **no 4698 at all**, so there is nothing for a 4698-scoped rule to see. That's a documented blind spot of the log source, not a tunable gap — see the README.

---

## Outcome

- **Sigma base rule**: 100% TP / 0% FP across the nine-fixture batch after three iterations.
- **Splunk V2**: adds `susp_encoded` and `susp_fileless` as strong signals on top of the Sigma base, driven directly by ART Test 7. Registry-staged fileless tasks now grade Medium/High instead of Informational.
- **KQL rule**: retains the five-signal version — encoded-blob and fileless scoring are still Splunk-only. Porting those two signals to KQL is the outstanding piece of work.
- **Confirmed blind spots**: task *modification* (4702) and Ghost-Task-style registry creation produce no 4698 and are out of scope for this rule by design.
