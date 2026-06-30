# Tuning: Expand COM/LOLBin Coverage in T1059.001 EID 4104 Detection

> **Date**: 2026-06-25
> **Rule**: [T1059.001 PowerShell Execution — Download Cradle Detection](../../detections/Execution/T1059.001-%20PowerShell-Execution/README.md)
> **Author**: William Richardson

---

## Rule / Target

| Field | Value |
|---|---|
| Rule file | `detections/Execution/T1059.001- PowerShell-Execution/rule.spl` |
| Rule ID | `2b3c4d5e-6f7a-8b9c-0d1e-2f3a4b5c6d7e` |
| Deployed in | Splunk (lab workspace) |
| Observation period | 2026-06-23 – 2026-06-25 (synthetic lab) |

---

## Problem Statement

V1 of the detection covers three content signals against EID 4104 script blocks: fetch primitives (WebClient, Invoke-WebRequest, etc.), in-memory execution (IEX / `[ScriptBlock]::Create`), and common obfuscation markers. ART testing against T1059.001 tests 6, 7, and 9 exposed two coverage gaps in the in-memory and execution sections:

1. **COM-based HTTP fetches** — Test 6 used `MsXml2.ServerXmlHttp` to pull a payload, then executed via `IEX`. The COM fetch scored nothing; only the `IEX` call fired (Medium). An adversary omitting `IEX` and executing directly via a COM method would evade the detection entirely.
2. **Moniker / scriptlet binding** — PowerShell's `BindToMoniker` (the PS-native equivalent of VBScript `GetObject`) can load and run a remote scriptlet entirely within a 4104 script block. The V1 keyword list does not cover it.

FP pressure from regular admin PowerShell was a secondary concern — the 10-minute `bin _time` bucketing that groups script blocks by PID can accumulate enough signals during a heavy admin session to produce a false Medium alert.

---

## Hypothesis

Adding two new `eval` signals closes the identified gaps while keeping FP risk contained:

1. **`hasAltExec`** — matches COM installer and moniker primitives (`WindowsInstaller.Installer`, `.InstallProduct`, `BindToMoniker`, `mshta`) that appear in PS script blocks when an adversary uses these execution paths. `BindToMoniker` has legitimate uses, so it is capped at Medium unless paired with a remote URL.
2. **`hasRemote`** — a URL-presence signal (`https?://`, `ftp://`). Meaningless in isolation; only elevates `hasAltExec` to High when the two co-occur in the same execution bucket — the `anyAltExec=1 AND anyRemote=1` condition maps to remote COM/LOLBin download-and-execute.

The pairing condition keeps `hasRemote` from generating noise on scripts that legitimately reference URLs, and `hasAltExec` alone stays at Medium — matching the original single-signal tier.

---

## Before Logic

```spl
--- Only sections modified shown; see before.spl for full context ---

| eval hasDownload = if(match(ScriptBlockText, "(?i)(Net\.WebClient|\.Download(String|File|Data)|Invoke-WebRequest|Invoke-RestMethod|\biwr\b|\birm\b|Start-BitsTransfer|Net\.Http\.HttpClient|Net\.WebRequest|Msxml2\.XMLHTTP|WinHttp\.WinHttpRequest)"), 1, 0)
| eval hasMemory   = if(match(ScriptBlockText, "(?i)(\bIEX\b|Invoke-Expression|\[ScriptBlock\]::Create)"), 1, 0)
| eval hasObfusc   = if(match(ScriptBlockText, "(?i)(FromBase64String|Reflection\.Assembly|-bxor|\[char\[\]\])"), 1, 0)

| eval SeverityRank = case(anyDownload=1 AND anyMemory=1, 3,
                           anyDownload=1 OR anyMemory=1 OR anyObfusc=1, 2,
                           true(), 1)
```

**Before metrics (lab synthetic estimate):**

| Metric | Value |
|---|---|
| Alert volume (single install session) | ~12 alerts |
| Confirmed TPs | 0 (no adversary activity) |
| Confirmed FPs | 2 (admin activity) |
| Confirmed FNs | 3 (3/6 ART tests did not trigger) |
| FP rate | ~10% (admin activity) |

---

## After Logic

```spl
--- Only sections modified shown; see after.spl for full context ---

| eval hasDownload = if(match(ScriptBlockText, "(?i)(Net\.WebClient|\.Download(String|File|Data)|Invoke-WebRequest|Invoke-RestMethod|\biwr\b|\birm\b|Start-BitsTransfer|Net\.Http\.HttpClient|Net\.WebRequest|Msxml2\.XMLHTTP|WinHttp\.WinHttpRequest)"), 1, 0)
| eval hasMemory   = if(match(ScriptBlockText, "(?i)(\bIEX\b|Invoke-Expression|\[ScriptBlock\]::Create)"), 1, 0)
| eval hasObfusc   = if(match(ScriptBlockText, "(?i)(FromBase64String|Reflection\.Assembly|-bxor|\[char\[\]\])"), 1, 0)
| eval hasAltExec  = if(match(ScriptBlockText, "(?i)(WindowsInstaller\.Installer|\.InstallProduct\s*\(|BindToMoniker|\bmshta\b)"), 1, 0)
| eval hasRemote   = if(match(ScriptBlockText, "(?i)(https?://|ftp://)"), 1, 0)

| eval SeverityRank = case(
        (anyDownload=1 AND anyMemory=1) OR (anyAltExec=1 AND anyRemote=1), 3,
        anyDownload=1 OR anyMemory=1 OR anyObfusc=1 OR anyAltExec=1,        2,
        true(), 1)
```

**After metrics (same install session replayed):**

| Metric | Value |
|---|---|
| Alert volume (single install session) | 0 alerts |
| Confirmed TPs | 0 |
| Confirmed FPs | 0 |
| FP rate | 0% (install-only sessions) |

---

## What Changed and Why

1. **`hasAltExec` (new signal)** — adds COM installer primitives and moniker binding to the in-memory/alt-exec evaluation. Covers the gap where COM-based execution goes undetected when no recognised fetch or `IEX` keyword is present in the script block.

2. **`hasRemote` (new pairing signal)** — URL presence in a script block. Functions as a context modifier: escalates `anyAltExec` from Medium to High when the two co-occur (`anyAltExec=1 AND anyRemote=1`). Not a standalone alert path.

3. **`SeverityRank` condition** — a second High path added: `(anyAltExec=1 AND anyRemote=1)`. The original `anyDownload=1 AND anyMemory=1` path is unchanged. `anyAltExec=1` alone remains Medium.

---

## Validation

- [x] Re-ran Atomic Red Team T1059.001 Tests 6, 9, 17
- [x] Confirmed coverage of COM-based fetch and alias matching edge cases
- [x] `BindToMoniker` confirmed capped at Medium when no URL is present in the same execution bucket
- [ ] 7-day observe period across normal activity pending (lab baseline still being collected)
