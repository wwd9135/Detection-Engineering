# Analysis — Run Key FP Reduction

## Scope

This analysis covers the value of adding 

## Data

All figures are synthetic estimates based on a single lab machine running minimal software. Real enterprise volumes would be orders of magnitude higher.

| Scenario | Before (alerts) | After (alerts) | Reduction |
|---|---|---|---|

## Key Finding

The `msiexec.exe` filter accounted for all observed FPs in the lab. The filter is path-anchored to the system directory, so a trojanised `msiexec.exe` placed in a non-standard path would NOT be excluded.

## Risk of the Filter

The accepted risk: a malicious payload that somehow hijacks `msiexec.exe` from `C:\Windows\System32\` to write a run key would be excluded. This scenario requires the adversary to have already achieved significant code execution at a privilege level that would allow replacing a system binary — at that point, run-key persistence is not the primary concern. Risk accepted.

## Next Tuning Candidate

Browser auto-update processes (e.g., `GoogleCrashHandler.exe`, `DiscordUpdateService.exe`) writing run keys are the next-largest source of expected FPs in a typical desktop environment. Defer until baseline observation data is available.
