# 

## Manual trigger validation — T1218.005/010/011

**Approach:** Conducted manual interactive trigger validation on a single Windows test box, cross-referencing each attempt against Sysmon EID 1 in Splunk (`ProcessGuid`/`ParentProcessGuid` chains) to confirm both process creation and the specific command-line signal each Sigma selection targets.

**Key findings:**
- Confirmed `selection_script_html_abuse` (rundll32) end-to-end: `cmd.exe → rundll32.exe (url.dll,OpenURL) → msedge.exe` captured cleanly in Sysmon, validating the `url.dll,OpenURL` string match against real telemetry.
- Confirmed the mshta child-spawn signal (`mshta.exe → calc.exe`) using a saved `.hta` file rather than an inline command — this is the mechanism the rule's "mshta spawning a shell/script host" logic is designed to catch.
- Confirmed `WScript.Shell` object creation is not blocked by WSH policy on the test box (`cscript` + `.vbs` executed successfully), ruling out Windows Script Host GPO restriction as an environmental confound for this box.
- Ruled out AV, ASR, and AppLocker/WDAC as blockers during this session — initial "no execution" results were misattributed to policy blocking before the real cause was found.
- **Root cause of repeated "nothing executes" results was not a security control** — it was character corruption from typing/pasting nested-quote command lines into `cmd.exe`/PowerShell (smart-quote substitution) and Notepad silently adding a BOM to saved `.vbs` files, producing a VBScript compilation error (800A0408) rather than a clear block/deny signal.
- Corrected a data-source mapping error found during this work: Sysmon EID 10 is `ProcessAccess`, not `FileCreate` (`FileCreate` is EID 11) — relevant if EID 10 is ever pulled into this rule's correlation logic.
- Confirmed the Splunk ingestion pipeline for Sysmon is unrestricted (no whitelist applied to the `Microsoft-Windows-Sysmon/Operational` input) — an earlier concern about a Security-log EventID whitelist was scoped only to scheduled-task auditing (4698–4702, 1102) and does not affect this rule's data source.

## Chainsaw validation

< table of the test names, ID they target, description>
| MITRE TTP | Category | Name | Desciption | MisFire rate |
|-----------|
| T1218.005 | Malicious |  | | |
| T1218.005 | Malicious |  | | |
| T1218.005 | Malicious |  | | |
| T1218.010 | Malicious |  | | |
| T1218.010 | Malicious |  | | |
| T1218.010 | Malicious |  | | |
| T1218.011 | Malicious |  | | |
| T1218.011 | Malicious |  | | |
| T1218.011 | Malicious |  | | |
| T1218.005 | Benign    |  | | |
| T1218.005 | Benign    |  | | |
| T1218.005 | Benign    |  | | |
| T1218.010 | Benign    |  | | |
| T1218.010 | Benign    |  | | |
| T1218.010 | Benign    |  | | |
| T1218.011 | Benign    |  | | |
| T1218.011 | Benign    |  | | |
| T1218.011 | Benign    |  | | |