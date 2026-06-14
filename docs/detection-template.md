# Detection README Template (ADS Framework)

Copy this template into every `detections/{tactic}/{technique}/README.md`.
Replace every `<!-- ... -->` placeholder. Remove the italicised guidance lines before committing.

Based on the [Palantir Alert & Detection Strategy (ADS) Framework](https://github.com/palantir/alerting-detection-strategy-framework).

---

# {RULE TITLE}

> **Technique**: {ATT&CK Technique ID} — {Technique Name}
> **Tactic**: {ATT&CK Tactic}
> **Severity**: {Critical / High / Medium / Low}
> **Status**: {Stable / Experimental / Deprecated}

---

## Goal

<!-- One paragraph. Describe the adversary behaviour this detection is meant to catch, in plain English.
     Answer: "What is the attacker doing, and why does it matter?" -->

{Description of the attacker behaviour being detected and why it is security-relevant.}

---

## Categorisation

| Field | Value |
|---|---|
| ATT&CK Tactic | {Tactic name and ID, e.g. Persistence (TA0003)} |
| ATT&CK Technique | {Technique name and ID, e.g. Boot or Logon Autostart Execution: Registry Run Keys (T1547.001)} |
| Data Source | {Sysmon / DeviceRegistryEvents / etc.} |
| Log Category | {Sigma logsource category, e.g. `registry_set`} |
| Platform | {Windows / Linux / macOS / Network} |

---

## Strategy Abstract

<!-- One paragraph. How does the detection work at a high level?
     Describe the logic — what events are selected, what filters are applied, what the condition tests. -->

{High-level description of the detection logic: what events are queried, what fields are tested, how the condition works.}

---

## Technical Context

<!-- Two to four paragraphs covering:
     1. How the attack technique works mechanically.
     2. What telemetry is generated and by what data source.
     3. Why this specific field/value combination catches it.
     4. Any important subtleties (e.g., field encoding, case sensitivity, wildcard scope). -->

### Attack Mechanics

{Explanation of how the technique is executed by an adversary.}

### Telemetry

{What log source generates the event, which Sysmon event ID / Windows event ID / etc., and what fields are populated.}

### Detection Logic

{Why the specific field matches in the rule reliably identify malicious behaviour while remaining as specific as possible.}

---

## Blind Spots & Assumptions

<!-- Be honest. A detection with known gaps documented is better than one that pretends to be complete.
     Use a bulleted list. -->

**Assumptions:**
- {e.g., Sysmon is deployed with a configuration that captures registry_set events (Event ID 13).}
- {e.g., The endpoint forwards logs to Sentinel within N minutes.}

**Blind Spots:**
- {e.g., An adversary writing directly to a registry hive file on disk (offline) would not generate a registry_set event.}
- {e.g., Living-off-the-land binaries (reg.exe) with obfuscated key paths may bypass the wildcard match.}
- {e.g., 32-bit process registry redirection (Wow6432Node) is NOT covered by this rule — see T1547.001-wow6432.}

---

## False Positives

<!-- Known benign triggers. Be specific — generic "legitimate software" is not useful. -->

- {e.g., Software installers (e.g., Google Chrome, Adobe Reader) routinely write to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` as part of auto-update setup.}
- {e.g., Endpoint management tooling (e.g., SCCM, Intune) may write run-key entries as part of policy enforcement.}
- {e.g., Developers running locally compiled applications that register a run key during testing.}

---

## Priority / Severity

**Severity: {Critical / High / Medium / Low}**

{Reasoning for the severity rating. Consider: how reliably does this technique lead to persistence? How hard is it to detect by other means? How common is the FP rate?}

---

## Validation

<!-- Link to validation.md and emulation/ test. Describe at a high level what test was run and what was observed. -->

See [validation.md](validation.md) for the full test record.

**Test used**: {Atomic Red Team test ID and name, or description of manual test}
**Result**: {Rule fired / Did not fire (with explanation)}
**Evidence**: {Link to screenshot or log excerpt in validation.md}

---

## Response

<!-- What should an analyst do when this alert fires? Step by step, scoped to what matters. -->

1. **Identify the process** — which process (`Image` / `InitiatingProcessFileName`) wrote the run-key value? Is it a known-good installer or an unexpected binary?
2. **Examine the value** — what executable does the registry value point to? Does it exist on disk? Is it signed?
3. **Check for lateral movement** — is the same key set across multiple hosts at the same time (lateral spread)?
4. **Review process tree** — what spawned the process that wrote the key? Look for suspicious parent/child chains.
5. **Contain if malicious** — isolate the host, preserve forensic artefacts (registry hive, memory if still active), initiate IR.

---

## References

- [MITRE ATT&CK — {Technique ID}](https://attack.mitre.org/techniques/{TECHNIQUE-ID-URL}/)
- {Additional references: threat intel reports, blog posts, CVE advisories, malware analyses.}
