# Tuning Record Template

Copy this into `tuning/{slug}/README.md` for each tuning effort.
Replace every `<!-- ... -->` placeholder. One file per discrete tuning change.

---

# Tuning: {Short Description of the Change}

> **Date**: {YYYY-MM-DD}
> **Rule**: [{Rule title}](../detections/{tactic}/{technique}/README.md)
> **Author**: {your name / handle}

---

## Rule / Target

| Field | Value |
|---|---|
| Rule file | `detections/{tactic}/{technique}/rule.yml` |
| Sigma rule ID | `{UUID}` |
| Deployed in | Microsoft Sentinel |
| Observation period | {Start date} – {End date} |

---

## Problem Statement

<!-- What was the observed problem? Be concrete — include approximate alert volume, % FP rate, or analyst-hours wasted. -->

{Description of the noise problem. E.g.: "This rule generated ~40 alerts/day in the home lab. Manual review confirmed that ~35 of those were benign software installers writing expected run-key entries. The FP rate was approximately 87%, making the rule practically un-actionable."}

---

## Hypothesis

<!-- What do you think is causing the noise, and what change do you expect to fix it? -->

{E.g.: "The noise originates from a small, enumerable set of known-good installers. Adding a filter on `Image` paths matching known installer directories (`C:\Program Files\`, `C:\Windows\Installer\`) should eliminate the bulk of FPs without suppressing adversarial activity, which typically originates from user-writable paths like `%TEMP%` or `%APPDATA%`."}

---

## Before Logic

```yaml
# Relevant excerpt from rule.yml BEFORE the change
detection:
  selection:
    EventType: SetValue
    TargetObject|contains:
      - '\CurrentVersion\Run\'
      - '\CurrentVersion\RunOnce\'
  condition: selection
```

**Before metrics:**

| Metric | Value |
|---|---|
| Alert volume (period) | {e.g., 280 alerts / 7 days} |
| Confirmed TPs | {e.g., 2} |
| Confirmed FPs | {e.g., 245} |
| Unknown / unreviewed | {e.g., 33} |
| FP rate (reviewed) | {e.g., ~99%} |

---

## After Logic

```yaml
# Relevant excerpt from rule.yml AFTER the change
detection:
  selection:
    EventType: SetValue
    TargetObject|contains:
      - '\CurrentVersion\Run\'
      - '\CurrentVersion\RunOnce\'
  filter_known_installers:
    Image|startswith:
      - 'C:\Program Files\'
      - 'C:\Program Files (x86)\'
      - 'C:\Windows\Installer\'
  condition: selection and not filter_known_installers
```

**After metrics (same observation period replayed):**

| Metric | Value |
|---|---|
| Alert volume (period) | {e.g., 35 alerts / 7 days} |
| Confirmed TPs | {e.g., 2} |
| Confirmed FPs | {e.g., 8} |
| Unknown / unreviewed | {e.g., 25} |
| FP rate (reviewed) | {e.g., ~80% — further tuning needed} |

---

## What Changed and Why

<!-- Explain each change at the field level. If you dropped a filter, explain why it was safe to drop it.
     If you added an exception, explain why the excepted behaviour is definitely benign. -->

1. **Added `filter_known_installers`** — processes launching from standard Windows installer directories are almost exclusively legitimate software deployments. Adversary payloads writing run keys almost never originate from these paths.
2. **Condition changed to `selection and not filter_known_installers`** — standard Sigma negative-filter pattern.

**TP preservation check**: The Atomic Red Team T1547.001 test (which uses `cmd.exe` from `C:\Windows\System32\`) is NOT excluded by this filter and still fires. Confirmed by re-running the emulation after the filter was applied.

---

## Validation

<!-- Confirm the tuning change did not suppress true positives. -->

- [ ] Re-ran emulation test after applying filter — rule still fired.
- [ ] Re-ran KQL query against historical telemetry — TP events still returned.
- [ ] Filter logic reviewed for path-traversal or case-sensitivity edge cases.

**Emulation test reference**: [emulation/{technique}/README.md](../emulation/)

---

## Outstanding Issues / Next Steps

<!-- What's still noisy? What's the plan for the next tuning pass? -->

- {e.g., A further ~25 alerts per week remain un-triaged. Hypothesis: these are developer machines running custom scripts. Next step: add a filter for developer user accounts if a stable allowlist can be defined.}

---

## Date

{YYYY-MM-DD}
