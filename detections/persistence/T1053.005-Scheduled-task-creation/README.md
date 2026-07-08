# Scheduled Task Creation — Persistence via Windows Task Scheduler

> **Technique**: T1053.005 — Scheduled Task/Job: Scheduled Task
> **Tactic**: Persistence (TA0003)
> **Severity**: Tiered — Informational / Medium / High (weighted score)
> **Status**: Stable

---

## Goal

Detect the creation of malicious scheduled tasks, or tasks that contribute to an adversary's attack chain in any capacity. This is an atomic rule that assesses the full task definition carried by Windows Security Event ID 4698 to decide whether a task creation looks like genuine admin activity, using a weighted severity score rather than a binary match — suspicious arguments, staging paths, script-engine payloads, encoded commands and registry-staged (fileless) payloads each contribute points, and the total maps to an alert tier.

The deliberate scope is **creation only**. Modification, enable/disable and deletion are separate behaviours with separate event IDs, and folding them all into one rule makes it broad, noisy and hard to maintain. Lifecycle correlation (creation → execution, creation → deletion-of-evidence) belongs at the platform's correlation layer, not inside the base rule.

---

## Known Real-World Usage

Scheduled tasks are one of the most heavily used persistence mechanisms on Windows because the scheduling itself is a native, living-off-the-land action — nothing needs to be dropped to disk to schedule execution.

- **Tarrask (HAFNIUM)** — created "hidden" scheduled tasks and then deleted the task's Security Descriptor registry value to hide it from `schtasks /query` and the Task Scheduler UI. Notable here because the *creation* event is the last reliable trace before the hiding step ([Microsoft write-up](https://www.microsoft.com/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/)).
- **Qakbot** — persistence via `schtasks` launching cmd → PowerShell with a base64 payload; the same chain is exercised by Atomic Red Team Test 7 and directly drove this rule's fileless/encoded signals.
- **APT29, FIN7 and numerous ransomware affiliates** — documented on the [ATT&CK technique page](https://attack.mitre.org/techniques/T1053/005/) using scheduled tasks for both persistence and lateral execution (remote task creation over SMB/RPC).

---

## Categorisation

| Field | Value |
|---|---|
| ATT&CK Tactic | Persistence (TA0003) |
| ATT&CK Technique | Scheduled Task/Job: Scheduled Task (T1053.005) |
| Data Source | Windows Security Event ID 4698 (a scheduled task was created) |
| Log Category | `windows` / `security` |
| Platform | Windows |
| SIEM | Microsoft Sentinel (KQL) · Splunk (SPL) · Sigma base (`rule.yml`) |

---

## Strategy Abstract

There are half a dozen front doors for creating a scheduled task — `schtasks.exe`, the PowerShell `*-ScheduledTask` cmdlets, the Task Scheduler MMC, direct COM (`ITaskService`) calls, WMI, and remote creation — and watching each gateway separately means six brittle rules. EID 4698 collapses all of them into one event at the point that matters: the task registration itself. Its XML payload (`TaskContent`) carries the **full task definition** — action, arguments, working directory, triggers and run-as principal — which is far richer than any process-creation view of the same activity.

The rule scores each 4698 across three signal categories:

1. **WHERE it runs** — the action executes from a world-writable/staging folder (`\Users\Public\`, `%TEMP%`, `\ProgramData\`, `\Downloads\`, …) or launches a scripting-engine file type (`.ps1`, `.vbs`, `.js`, `.hta`, …). The extension match is anchored to the closing XML tag of the launched file so it can't fire on an extension merely mentioned inside an argument string.
2. **HOW it runs** — the action carries interpreter flags used to force, hide or obfuscate execution (`-w hidden`, `bypass`, `-noni`, `IEX`, `FromBase64String`, `mshta`/`rundll32`/`regsvr32`), an encoded command with a real base64 blob (`susp_encoded`), or a registry-staged fileless payload that both reads a registry value and decodes-or-executes it (`susp_fileless`).
3. **PRIVILEGE × TRIGGER** — the task both auto-starts (boot/logon trigger) *and* runs elevated (SYSTEM / `HighestAvailable`). Neither is suspicious alone — admin tasks are routinely elevated, and persistence-by-design software auto-starts — but together they earn a synergy bonus.

The Sigma base rule (`rule.yml`) expresses this as a flat boolean condition, since Sigma has no scoring; the SPL and KQL ports implement the weighted score, parse the task XML into per-action fields, and emit a graded alert. The Splunk rule is the V2 reference implementation (seven signals); the KQL rule currently carries the original five — see Validation.

Deliberately **not** scored: time/calendar triggers (far too common in benign tasks — time-based persistence is caught by the content signals instead) and bare `powershell.exe` as a command (legitimately everywhere).

---

## Technical Context

### Attack Mechanics

| Creation method | Detection note |
|---|---|
| `schtasks.exe /create` | Most common, most logged, easiest to catch on the command line — but 4698 sees it regardless |
| PowerShell `New-/Register-ScheduledTask` | Same COM API underneath, different process tree — command-line rules miss it, 4698 doesn't |
| Direct COM API (`ITaskService`) | Bypasses schtasks.exe entirely; no command-line artifact at all. 4698 still fires |
| WMI `RegisterByXml` | Ditto — the task XML lands in 4698's `TaskContent` |
| Remote creation (`schtasks /s <host>`, PS remoting) | 4698 is logged on the *target* — the lateral-movement angle |
| Registry manipulation ("Ghost Task") | Writes the task keys directly under SYSTEM without touching the scheduler service — **no 4698 is emitted**; see Blind Spots |

### Telemetry

**Windows Security EID 4698** (requires "Audit Other Object Access Events"):

| Field | Use |
|---|---|
| `TaskContent` | The full task-definition XML — actions, arguments, triggers, principal. The core detection surface |
| `TaskName` | Task path/name — pivot key for lifecycle follow-up (4699/4700/4701/4702) |
| `SubjectUserName` / `SubjectDomainName` | Who created the task — first triage question |
| `Computer` / `host` | Where it was created |

Neighbouring events an analyst will want during triage (not used by the rule): Security 4699–4702 (delete/enable/disable/update) and the `Microsoft-Windows-TaskScheduler/Operational` log (EIDs 106/140/141/200/201) for per-run execution history.

### Detection Logic

Weighted score per event (Splunk V2 weights):

| Signal | Weight | Rationale |
|---|---|---|
| `susp_path` — staging/world-writable folder | 2 | SYSTEM and real installers essentially never register tasks out of `\Users\Public\` etc. |
| `susp_ext` — script-engine payload, anchored to launched file | 2 | Tasks legitimately launch exes; a `.ps1`/`.vbs`/`.hta` as the scheduled action is worth a look |
| `susp_args` — interpreter/obfuscation flags, LOLBins | 2 | `-w hidden`, `bypass`, `IEX`, `FromBase64String`, `mshta`, … |
| `susp_encoded` — `-enc` switch followed by a real base64 blob | 2 | Blob requirement stops `-ExecutionPolicy` and friends false-matching |
| `susp_fileless` — reads a registry value AND decodes/executes it | 2 | Registry-staged payloads (ART Test 7, Qakbot pattern); both halves required |
| `susp_elevation` — SYSTEM / `HighestAvailable` | 1 | Normal alone for admin tasks |
| `susp_trigger` — boot/logon trigger | 1 | Normal alone for legitimate auto-start software |
| Synergy: elevation AND trigger | +1 | Auto-starting *and* elevated is the persistence-shaped combination |

| Tier | Score | Meaning |
|---|---|---|
| **High** | ≥ 4 | Two strong signals, or a strong signal plus elevated auto-start |
| **Medium** | 3 | A strong signal plus one weak, or elevated AND auto-start together |
| **Informational** | 2 | A single strong signal — logged, suppressed from analyst queues |
| None | ≤ 1 | Elevation-only / trigger-only never fire on their own |

---

## Blind Spots & Assumptions

**Assumptions:**

- 4698 auditing is actually enabled ("Audit Other Object Access Events" → Success). It is **not on by default** — this is the single deployment precondition that decides whether the rule sees anything at all. Verify per GPO rollout.
- Security log events reach the SIEM (Splunk `XmlWinEventLog:Security` / Sentinel `SecurityEvent` via AMA) with reasonable latency.
- For Splunk: `Splunk_TA_windows` extracts the EventData fields; `TaskContent` is pulled from `_raw` and entity-decoded in the rule regardless.

**Blind Spots:**

- **Task modification (4702)** — create a boring task, then point it at the payload afterwards. This rule only reads 4698; a sibling rule applying the same scoring to 4702 is the natural next build.
- **Enable/disable of pre-existing tasks (4700/4701)** — a malicious task created before rollout can be re-enabled without a creation event. Low probability, zero on new builds; an audit of existing tasks closes it.
- **Ghost Tasks / SD-value deletion (Tarrask)** — registry-level task creation under SYSTEM emits no 4698 at all (confirmed via ART Test 10). Needs a registry-telemetry rule, not a 4698 rule.
- **Jump scripts** — 4698 shows what the task launches, not what that thing goes on to do. `TaskScheduler → innocuous.ps1 → payload` scores only on the visible layer; the T1059.001 script-block rule covers the execution end.
- **Sigma-base fidelity** — the portable Sigma rule matches everything against the single `TaskContent` blob and can't score; the graded logic lives in the SPL/KQL ports.

---

## False Positives

- **Software installers and updaters** (Adobe, Chrome, Java, AV agents, backup tools) create tasks constantly, often as SYSTEM, often from temp paths mid-install. This is the biggest source — by design it grades rather than suppresses (an unsigned exe scheduled out of user Temp *should* surface once), and known updaters get allow-listed per environment on `SubjectAccount` + `Command`.
- **Windows Update / servicing stack** tasks.
- **SCCM / Intune / RMM tooling** legitimately creates and deletes tasks at volume.
- **Admin automation via `schtasks`** — legitimate `-enc` or `IEX` usage in scheduled actions will score. Baseline known admin accounts/hosts before raising the firing floor.

The firing floor (`Score ≥ 2`) and the High cut (`≥ 4`) are both single-line tuning knobs in the SPL/KQL — documented in the rule headers.

---

## Priority / Severity

Tiered by score rather than a single static severity. The High tier corresponds to combinations with genuinely low benign rates (staging path + script payload, encoded blob + hidden window, fileless registry-staged execution); Medium marks single-strong-signal-plus-context cases worth an analyst's time; Informational exists so borderline events (one suspicious property, nothing else) are recorded for hunting and correlation without paging anyone. Elevation or auto-start alone never fire — that decision is what keeps this rule liveable next to the constant hum of legitimate task creation.

---

## Validation

See [Validation.md](Validation.md) for the full test record.

**Round 1 — Chainsaw fixture batch** (Sigma rule): five malicious / five benign real 4698 EVTX slices generated by [Telemetry_Collector.ps1](Telemetry_Collector.ps1), asserted fire/quiet via the repo's pytest harness. Three tuning iterations took it from 80% TP / 20% FP to **100% TP / 0% FP** — the fixes were adding `\Users\Public\` to the staging paths and anchoring extension matches to the launched file.

**Round 2 — Atomic Red Team** (Splunk SPL): ART Test 7 (registry-staged base64 payload) initially graded only Informational and drove the V2 additions — `susp_fileless` and `susp_encoded`. Post-tuning it grades Medium/High consistently. Tests 1/4/6 are inert as shipped and correctly stay quiet; Test 10 (Ghost Task) emits no 4698 and is a documented blind spot. A full replay of the fixture set through Splunk graded every malicious creation Medium or High with one benign Informational and no benign alerts above the floor.

---

## Detection Output

Splunk V2 SPL rule — ART Test 7 (registry-staged fileless task) firing post-tuning, 2026-07-08. The decoded registry-read-and-IEX chain is visible in the Arguments column.

![Splunk alert output — T1053.005 ART Test 7 result](<Assets/Screenshot 2026-07-08 175536.png>)

---

## Response

When this alert fires, an analyst should:

1. **Triage the creation event itself** — is `SubjectAccount` an expected admin/service account or a standard user? Does `Command`/`Arguments` point at a staging path? Is the payload encoded (`-enc <base64>`) or pulled from the registry? Decode any blob:
   `powershell -c "[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('<blob>'))"`
2. **Check the persistence shape** — does the task auto-start (`TriggerTypes` = Logon/Boot) *and* run elevated (SYSTEM / HighestAvailable)? Auto-start + elevated + staging path together is a strong persistence signal.
3. **Scope the task's lifecycle** — query 4699/4700/4701/4702 for the same `TaskName` on the same host: has it been modified, disabled or deleted since creation? Deletion shortly after creation is itself suspicious (evidence cleanup).
4. **Pull execution history** — run history is *not* in the Security log. On the host: `Get-ScheduledTaskInfo` for last/next run, and the `Microsoft-Windows-TaskScheduler/Operational` log (EIDs 100/102/200/201) for per-run results.
5. **Examine the full task XML** — the 4698 `TaskContent` field carries the complete definition; check working directory, author, and any second `<Exec>` action hiding behind the first.
6. **Hunt for spread** — search the same `TaskName` / `Command` across other hosts; remote task creation is a standard lateral-movement move, so check logon events around the creation time on the target.
7. **Contain if malicious** — isolate the device, capture the task XML and any binaries it references, then begin DFIR procedures. If benign admin/automation, add `SubjectAccount` + `Command` to the tuning allow-list instead of weakening the rule.

---

## References

- [MITRE ATT&CK — T1053.005](https://attack.mitre.org/techniques/T1053/005/)
- [Atomic Red Team — T1053.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md)
- [Microsoft — Tarrask malware uses scheduled tasks for defense evasion](https://www.microsoft.com/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/)
- [Microsoft Docs — Event 4698: A scheduled task was created](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698)
- [SigmaHQ — scheduled task rules](https://github.com/SigmaHQ/sigma/tree/master/rules/windows/builtin/security)
- [Dayachowdry — sentinel-kql T1053.005](https://github.com/Dayachowdry/detection-rules/blob/master/sentinel-kql/persistence/T1053.005-scheduled-task-creation.kql)
- [elastic/detection-rules — scheduled task rules](https://github.com/elastic/detection-rules/tree/main/rules/windows)
- [Palantir ADS Framework](https://github.com/palantir/alerting-detection-strategy-framework)
