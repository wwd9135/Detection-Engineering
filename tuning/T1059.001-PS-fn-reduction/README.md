# Tuning: Reduce FP Volume on Run-Key Detection from Software Installers

> **Date**: 2026-06-14
> **Rule**: [Windows Registry Run Key Persistence via Sysmon](../../detections/persistence/T1547.001-registry-run-keys/README.md)
> **Author**: William Richardson

---

## Rule / Target

| Field | Value |
|---|---|
| Rule file | `detections\Execution\T1059.001- PowerShell-Execution\rule.yml` |
| Rule ID | `2b3c4d5e-6f7a-8b9c-0d1e-2f3a4b5c6d7e` |
| Deployed in | Splunk enterprise (lab workspace) |
| Observation period | 2026-06-14 – 2026-06-20 (synthetic baseline estimate) |

---

## Problem Statement
Rule is written in splunk, targets T1059.001 PS exececution, log source Win event EID 4104. Focusing on executions related to downloading malicious content.

Initial version of the rule has three mechanism categories that can trigger an alert spawn. Disk downloads, obsfucation, in memory downloads.
The obsufucation & in memory sections are the focus area, not the wider rule. These sections pick up on the most common attacks robustly, but lack edge cases & fine tuning.

False positive generation is a concern regarding real admin activity, the mechanism developed blocks script blocks & PID together, useful for analysis if it's malicious, but it could trigger a FP during regular work since 10 minutes of PS scripting is bucketed together over time this could amount to an accidental trigger, this functionality needs tested carefully, a big script to discover what the max line count per bucket is, and a deliberate sprinkle of suspicious activity over a 10 minute period (needs to be according to the hour eg. 5.10-5.20 will never be 5.22-5.32).
---

## Hypothesis
After testing ART 8,9,17 its clear the alert needs slightly filtered to account for these tests, what im filtering for:

1. <INSERT LOGIC for in memory section>
2. <INSERT LOGIC for obfuscation section>

---

## Before Logic

```spl```
``` --- Only sections being modified shown, refer to full before/after.spl files for more context --- ```
| eval hasDownload = if(match(ScriptBlockText, "(?i)(Net\.WebClient|\.Download(String|File|Data)|Invoke-WebRequest|Invoke-RestMethod|\biwr\b|\birm\b|Start-BitsTransfer|Net\.Http\.HttpClient|Net\.WebRequest|Msxml2\.XMLHTTP|WinHttp\.WinHttpRequest)"), 1, 0)
| eval hasMemory   = if(match(ScriptBlockText, "(?i)(\bIEX\b|Invoke-Expression|\[ScriptBlock\]::Create)"), 1, 0)
| eval hasObfusc   = if(match(ScriptBlockText, "(?i)(FromBase64String|Reflection\.Assembly|-bxor|\[char\[\]\])"), 1, 0)

``` --- Change area 2- alertations to risk matrix deciding severity of the alert --- ```
| eval SeverityRank = case(anyDownload=1 AND anyMemory=1, 3,
                           anyDownload=1 OR anyMemory=1 OR anyObfusc=1, 2,
                           true(), 1)


**Before metrics (lab synthetic estimate):**

| Metric | Value |
|---|---|
| Alert volume (single install session) | ~12 alerts |
| Confirmed TPs | 0 (no adversary activity) |
| Confirmed FPs | 2                       |
| Confirmed FNs | 3 (3/6 atomics didn't trigger alert)
| FP rate | ~10% (Admin activity) |

---

## After Logic

```spl
```
``` --- Only sections being modified shown, refer to full before/after.spl files for more context --- ```

``` --- Change area 2- alertations to risk matrix deciding severity of the alert --- ```


**After metrics (same install session replayed):**

| Metric | Value |
|---|---|
| Alert volume (single install session) | 0 alerts |
| Confirmed TPs | 0 |
| Confirmed FPs | 0 |
| FP rate | 0% (during install-only sessions) |

---

## What Changed and Why

1. **

3. **Condition** — changed from __ to __

---

## Validation

- [x] Re-ran Atomic Red Team T1059.001 Tests 6--9,17
- [ ] Confirmed edge case coverage, paticularly string matching/ alias matching from PowerShell commands.
- [ ] 7-day observe period across normal activity pending (lab activity baseline still being collected).


