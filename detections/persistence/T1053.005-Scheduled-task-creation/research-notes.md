# Research notes — T1053.005 Scheduled task creation

*Working notes compiled during rule development. Not polished — this is the actual research trail.*

---

## Hypothesis

Adversaries use the Windows Task Scheduler to establish persistence, escalate privileges (via tasks running as SYSTEM), execute code at arbitrary times, or move laterally (remote task creation via SMB/RPC). It's one of the most heavily used persistence techniques because it's a native, "living off the land" mechanism — no malware needs to be dropped for the scheduling itself.

## ATT&CK page & research notes

| Method | Notes |
| --- | --- |
| `schtasks.exe /create /tn ... /tr ... /sc ...` | Most common, most logged, easiest to detect |
| PowerShell `New-ScheduledTask*` cmdlets | Same COM API underneath, different process tree |
| Direct COM API (`ITaskService`) via script/binary | **Bypasses schtasks.exe entirely** — no command-line artifact, only file/registry/ETW traces |
| Manually dropping .job/XML task files into `C:\Windows\System32\Tasks\` | Legacy/manual, may not trigger normal creation events if the scheduler service isn't told to reload |
| Task Scheduler MMC GUI | Rare for attackers but possible via RDP/interactive access |
| Remote creation via `schtasks /s <host>` or WMI/PowerShell remoting | Lateral movement angle — look for network logon types on the target |

The main focuses are creation via the GUI / PS executions & direct COM API. I need to target the creation event itself rather than scanning each gateway for a match — i.e. if there's an event that already correlates all these front doors into one log source, that makes my life a lot easier. That's 4698. One catch with 4698: it requires deliberate enabling via reg key / GPO rollout.

**Important defence evasion consideration** — from the ATT&CK page:

> Adversaries may also create "hidden" scheduled tasks (i.e. Hide Artifacts) that may not be visible to defender tools and manual queries used to enumerate tasks. Specifically, an adversary may hide a task from `schtasks /query` and the Task Scheduler by deleting the associated Security Descriptor (SD) registry value (where deletion of this value must be completed using SYSTEM permissions).[[4]](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_delete/registry_delete_schtasks_hide_task_via_sd_value_removal.yml)[[5]](https://www.microsoft.com/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/) Adversaries may also employ alternate methods to hide tasks, such as altering the metadata (e.g., `Index` value) within associated registry keys.

## Data source research

It's clear that to make this robust I need to focus specifically on creation of tasks — not deletions, modifications etc, as this would become too broad and either generate FPs or miss TPs, bad outcomes regardless. I'll aim for simplicity and find a couple of log sources specifically for creation, then consider creating rules to correlate creation → execution, or creation → defence evasion (e.g. deleting trace of the task they created — a common evasion technique).

I'm including the other EIDs for analyst benefit; they'll help with triage if this alert were to fire.

**1. Microsoft-Windows-TaskScheduler/Operational log** (often disabled by default — verify it's enabled)

| Event ID | Meaning |
| --- | --- |
| 106 | Task registered/created |
| 140 | Task updated/changed |
| 141 | Task deleted |
| 200 | Task executed (action started) |
| 201 | Task completed |
| 129 | Task launched with specific process ID/args |

**2. Security log (requires "Audit Other Object Access Events" / object access auditing enabled)**

| Event ID | Meaning |
| --- | --- |
| 4698 | Scheduled task created |
| 4699 | Scheduled task deleted |
| 4700 | Scheduled task enabled |
| 4701 | Scheduled task disabled |
| 4702 | Scheduled task updated |

4698's XML payload includes the **full task definition** (action, arguments, trigger, principal/run-as context) — this is gold for detection, far richer than the Operational log alone.

## Existing community rules reviewed

- [SigmaHQ — win_security_gpo_scheduledtasks.yml](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_gpo_scheduledtasks.yml) — basic Sigma rule, doesn't cover much ground, barely usable. Shows correct field names at least.
- [Dayachowdry — T1053.005-scheduled-task-creation.kql](https://github.com/Dayachowdry/detection-rules/blob/master/sentinel-kql/persistence/T1053.005-scheduled-task-creation.kql) — great rule, shows the most common child spawns, commands etc adversaries use.
- [elastic/detection-rules — persistence_scheduled_task_updated.toml](https://github.com/elastic/detection-rules/blob/e4bc385a8752c758c9da01cbee2592b251542655/rules/windows/persistence_scheduled_task_updated.toml) — identifies first-time modifications to scheduled tasks by user accounts, excluding system activity and machine accounts.

**Decision**: write my own Sigma rule. Community rules are too narrow — I'll take rule 2 above and tweak it to make it more powerful.

## Detection ideology & architecture

I'll be creating an atomic-style rule: single focus (task creation) and a single log source (EID 4698), but within this tight scope there will be breadth — enough to tackle the most popular threats adversaries pose when creating scheduled tasks.

The reasons for and against this method:

**Pros**

1. The rule is built for Sentinel/Splunk, so auto-correlation of alerts between related entities occurs platform-wide without configuration. If multiple of these atomic-style rules fire on an entity, the platform correlates the alerts into one incident, making analyst remediation/triage significantly quicker — and the segregation of the alerts makes the attack tree easier to follow than a single large alert.
2. Ongoing maintenance is simpler since only one log source is used.

**Cons**

1. If all rules aren't implemented simultaneously there will be large blind spots, reducing defence in depth — the opposite of the purpose of this detection. Example: if rules detecting PowerShell execution don't pick up on scheduled-task-based attacks.

As for what this rule will target specifically:

1. Suspicious child image spawn path & extensions
2. Suspicious commands in the arguments/parameter section
3. Trigger & user context (privileges the task runs under) in combination

## Chainsaw unit batch testing

Created a batch of malicious and benign Windows event logs (real 4698s exported per test case by `Telemetry_Collector.ps1`), ran the rule against them using Chainsaw via the pytest harness, and tuned to reduce the FP rate on the benign and the missed-TP rate on the malicious logs.

### What each set exercises

| # | Malicious | Hits |
| --- | --- | --- |
| 1 | `mal_schtask_encoded_powershell` | LOLBin + encoded args, via schtasks |
| 2 | `mal_pscmdlet_encoded` | Same, via `Register-ScheduledTask` (non-schtasks path) |
| 3 | `mal_wmi_registerbyxml_temp_path` | Suspicious path (`\Users\Public\`), via WMI |
| 4 | `mal_qakbot_pattern` | Real-world combo: cmd → powershell → base64 IEX. *Dropped — never built as a fixture; ART Test 7 exercises the identical chain, so building it twice added nothing.* |
| 5 | `mal_privesc_runlevel_highest` | SYSTEM + HIGHEST + suspicious path together |

| # | Benign | Purpose |
| --- | --- | --- |
| 1 | `benign_signed_backup_task` | Baseline clean case |
| 2 | `benign_system_maintenance_task` | SYSTEM alone shouldn't trip it — checks the rule isn't over-weighting RunLevel |
| 3 | `benign_clean_powershell_script` | powershell.exe present but *not* encoded — the sharpest test of the LOLBin criterion, since powershell.exe is legitimately common |
| 4 | `benign_installer_temp_task` | `%TEMP%` path but clean args — the single biggest real-world FP source. *Reclassified to malicious-expected in iteration 3: an unsigned exe running hourly out of user Temp should fire, and real environments allow-list their known updaters in the SIEM instead.* |
| 5 | `benign_user_logon_notepad` | Plain non-admin, no red flags at all |

### Results

Full detail and raw harness output in [Validation.md](Validation.md); the short version:

| Iteration | Benign FP rate | Malicious TP rate | What changed |
| --- | --- | --- | --- |
| 1 | 20% | 80% | Starting point — missed the `\Users\Public\` WMI fixture, false-positived on clean `.ps1` |
| 2 | 40% | 100% | Added `\Users\Public\` + widened staging paths; TP fixed but two benigns now firing |
| 3 | 0% | 100% | Extension match anchored to the launched file (`...ps1</Arguments>`); installer-in-Temp fixture reclassified as fire-worthy |

The extension anchoring was the useful trick: in the 4698 task XML, the file the task actually launches always manifests as e.g. `C:\Scripts\Cleanup.ps1</Arguments>`, so anchoring on the closing tag stops the rule matching the same extension mentioned incidentally elsewhere in the XML. Reduced FPs without giving up any TP.

## Atomic Red Team unit batch testing

Using the following tests to check the yml alert still works after conversion to Splunk's SPL, then a batch of ART tests to hunt missed ground / edge cases.

| Test | Creation method | Payload as-shipped | Exercises which criteria |
| --- | --- | --- | --- |
| #1 | schtasks.exe | `cmd.exe /c calc.exe` | LOLBin only (cmd.exe) — weak signal, no suspicious args |
| #4 | PS `Register-ScheduledTask` cmdlet | calc.exe | None of the criteria as shipped — calc.exe isn't a LOLBin or suspicious path |
| #6 | WMI `Invoke-CimMethod` RegisterByXml | notepad.exe | Same as #4 — inert payload |
| #7 | schtasks.exe, but base64 payload staged in the registry | cmd.exe → powershell.exe -Command IEX(...FromBase64String...) | LOLBin (cmd + powershell) **and** encoded/obfuscation pattern — the richest single test case |
| #10 | Registry manipulation (Ghost Task) | notepad.exe | Deliberately generates **no 4698 at all — known blind spot** |

Outcome: Test 7 was the only one that drove tuning — it exposed the registry-staged/fileless gap and led to the `susp_fileless` and `susp_encoded` signals in the SPL rule. Tests 1/4/6 are too benign to score (correctly — can't blanket-alert on all task creation), and #10 never produces the event this rule reads. Full write-up in [Validation.md](Validation.md).

### Likely FP sources (to watch in tuning)

- Software installers and updaters (Adobe, Google Chrome, Java, antivirus, backup agents) create tasks constantly, often as SYSTEM, often pointing at odd-looking temp paths during install.
- Windows Update and servicing stack tasks.
- SCCM/Intune/RMM tools legitimately create and delete tasks frequently.
- IT admin scripts using `schtasks` for legitimate automation — baseline known admin accounts/hosts.

## Blind spots & assumptions

The main one: attackers can evade by creating an inconspicuous task, then modifying it. Since my log source is only 4698 (task creation, not modification) it won't catch this — a separate detection covering 4702 with the same logic as this rule would easily cover it.

Attackers can use a jump script/program to get around the detection, i.e. TaskScheduler → .ps1 → malicious script/program, or run the malicious code in memory — 4698 can't check the contents of what the scheduled action goes on to execute.

Adversaries can enable a malicious task that was created before this rule was rolled out — enable/disable isn't caught by EID 4698. Low probability, and zero probability on new-build devices, but worth noting: an audit of existing scheduled tasks would improve assurance.
