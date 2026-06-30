# Research Notes — T1059.001 PowerShell Execution (Download Cradles)

*Working notes compiled during rule development. Not polished — this is the actual research trail.*

> **Scope decision:** this detection covers the **download-and-execute** slice of T1059.001 only,
> not all PowerShell execution. See *Detection Ideology* for why.

---

## TODO

- [x] Tighten hypothesis
- [x] Write up existing research so far
- [x] Fill in EID 4104 fields
- [x] Run the Atomic tests and record results — see validation.md (Tests 6, 7, 9)
- [x] Decide final tiering / correlation split — two base rules (sysmon.yml + rule.yml), correlation at platform layer
- [ ] Review download-cradle prior art in the two relevant SigmaHQ folders (see *Existing Community Rules*)
- [ ] Complete field-mapping verification for both log sources

---

## Starting Point & ATT&CK Page Notes

**Hypothesis (falsifiable):**
> If an adversary uses PowerShell to **download and execute** a payload, then the fetch primitive
> will appear *either* on the Sysmon EID 1 command line (when issued in cleartext) *or* in the
> 4104 script block (after the engine decodes any `-EncodedCommand`), and the launch context
> (suspicious parent and/or evasion flags) will appear on EID 1. A **two-layer** detection across
> EID 1 + 4104 should therefore catch the download-cradle pattern even when the command line is
> base64-encoded.

This is deliberately scoped to the download cradle so the rule is testable: I can generate the exact
behaviour with Atomic Red Team and assert fire-on-malicious / quiet-on-benign.

**Why downloads first:**
- Execution shells are the standard way to pull a second-stage payload past app-install / allow-list controls.
- T1059.001 spans many vectors; building one *good* detection beats one broad noisy one. (Trying to cover
  the whole technique in a single rule would mean correlating half a dozen event IDs — that's a correlation-layer
  job, not a base-rule job.)
- Strong, reliable telemetry from **Sysmon EID 1** (process creation) and **EID 4104** (script block logging).

---

## Detection Ideology

Detect the **mechanism, not the entity**. This is the **Pyramid of Pain** (Bianco): hashes/IPs/domains sit at the
bottom — an attacker rotates them in seconds. Techniques (TTPs) sit at the top — changing *how* they operate is
expensive. Rotating a C2 domain or renaming a payload is **indicator rotation**, not a zero-day; atomic indicators
are brittle *because* they're trivially rotated. That's the argument for targeting the download *mechanism*.

> The **attack surface** is infinite (endless URLs, payloads, exe names).
> The **mechanism surface** is small and fixed — PowerShell only has a handful of ways to actually pull
> bytes off the network, and the attacker is *forced* to use one of them. That bottleneck is the leverage.

So: alert on suspicious **activity & mechanisms**, not entities; don't try to block all PowerShell, and don't
over-suppress into blind spots. Tier confidence by **stacking conditions** rather than growing exclusion lists.

---

## Detection Architecture — Two Rules, Not One

A Sigma rule has **one `logsource`**. The launch signals (parent, evasion flags) live on `process_creation`;
the in-memory cradle content lives on `ps_script` (4104). You physically can't match both in one rule — so this
is **two base rules**, with any cross-layer combination handled in the **correlation layer**, not inside either rule.

| Rule | Log source | Catches | Unique value |
|------|-----------|---------|--------------|
| **Rule A** | Sysmon EID 1 (`process_creation`) | powershell.exe launched + **parent lineage** + **evasion flags** (`-enc`, `-w hidden`, `-ep bypass`) + cleartext fetch primitives | "the *launch* looked suspicious" — fires even when `-enc` hides the payload |
| **Rule B** | EID 4104 (`ps_script`) | fetch primitive + IEX/run-in-memory cradle in the **decoded** script block | "what it *actually did*" — encoding-resistant; this is where download detection primarily lives |

> **Correction to my earlier mental model:** download primitives are *primarily a 4104 thing*, not an EID 1 thing.
> On EID 1 they only show if they're in cleartext on the command line; `-enc` hides them. They survive into 4104
> because the engine had to decode them to run them. Overlap between the two rules on cleartext cases is
> *defence-in-depth*, not redundancy.

### Where the tiering lives
- **Within Rule A** (one log source): fetch + evasion + suspicious-parent can be separate selections and tiered
  in the `condition` (e.g. cradle alone = medium; cradle + flag/parent = high). This is fine inside one rule.
- **Across A and B** (two log sources): that combination is a **correlation-layer** job — see below. Do NOT try
  to cram cross-layer tiering into a base rule.

### Correlation layer (name the patterns)
- **Risk-Based Alerting (RBA)** — Splunk's term; each atomic signal writes a *risk contribution* to an
  entity (host/user) tagged to its ATT&CK technique; an incident fires only when *cumulative* risk crosses a
  threshold. This is exactly the "emit low/informational signals, let them stack" idea — it's a named, mature pattern.
- **Sentinel options for joining Rule A + Rule B:**
  1. **Explicit KQL join** in one scheduled analytics rule (DeviceId + time window). Deterministic, I own the
     logic, and it's the only version I can write a clean pass/fail unit test against. → *primary approach.*
  2. **Native incident grouping** — map both rules' Host entity; Sentinel groups alerts into one incident by
     shared entity without an explicit join. Lighter, less precise.
  3. **Fusion** — ML, one non-customisable rule per workspace. Custom rules are eligible *only if* they're
     **scheduled**, have **MITRE tactics mapped**, and emit **entity mappings**. It hunts cross-kill-chain
     multistage patterns — it won't reliably do "fire when A and B both hit the same host," and the logic is a
     black box. → treat as a *bonus* on top of the explicit join, not the primary mechanism.

  _[VERIFY: confirm current Fusion eligibility requirements against MS Learn before relying on it.]_

---

## Mechanisms

### Mechanism 1 — Parent image as a signal (confidence modifier, NOT a block/allow list)

Parent image never fires on its own — it **raises or lowers confidence**. There is no "malicious" parent and no
"safe" parent; the real question is *anomaly vs baseline* (is this parent spawning PowerShell normal for this host
and role?). The list below is **high-confidence tier-raisers** (an OR list that adds a tier), grouped by *why*:

**Office apps** (macro / phishing execution chain):
`winword.exe`, `excel.exe`, `powerpnt.exe`, `outlook.exe`, `mspub.exe`

**Script hosts / HTA** (dropper interpreters):
`wscript.exe`, `cscript.exe`, `mshta.exe`

**Signed LOLBin proxies** (execution laundering):
`regsvr32.exe`, `rundll32.exe`

**Server worker contexts** (webshell / SQL abuse):
`w3wp.exe`, `sqlservr.exe`

> Match against **lineage, not just the immediate parent** where the backend allows it — `winword.exe → cmd.exe
> → powershell.exe` defeats immediate-parent matching. Sysmon EID 1 carries only one level (`ParentImage`); MDE
> gives `InitiatingProcessParentFileName` (one extra level) — walk further via ProcessGuid chains in KQL. If stuck
> with single-level matching, note it as a blind spot rather than pretending the list covers it.

### Mechanism 2 — Command / script content matching (the bounded mechanism set)

Highest-fidelity approach — targets the top of the Pyramid of Pain.

**Fetch primitives** (pull bytes off the network — the bounded set; an OR list):
- `Net.WebClient` → `.DownloadString` / `.DownloadFile` / `.DownloadData`
- `Invoke-WebRequest` (+ aliases `iwr`, `curl`, `wget`)
- `Invoke-RestMethod` (+ alias `irm`)
- `Start-BitsTransfer` (also maps to **T1197**)
- `Net.Http.HttpClient`
- `[Net.WebRequest]::Create(...)`
- COM: `Msxml2.XMLHTTP`, `WinHttp.WinHttpRequest`

**Run-in-memory primitives** (turn the download into execution — file never touches disk → lives in **Rule B / 4104**):
- `IEX` / `Invoke-Expression`
- `&` (call operator) / `.Invoke()`
- `[ScriptBlock]::Create(...)`

**Evasion modifiers** (raise confidence when stacked — mostly EID 1 command-line flags):
- `-EncodedCommand` / `-enc` / `-e`
- `-WindowStyle Hidden` / `-w hidden`
- `-ExecutionPolicy Bypass` / `-ep bypass`
- `-NoProfile` / `-nop`, `-NonInteractive` / `-noni`
- `FromBase64String`, char-code arrays, string concat, backtick insertion (`` D`o`wnloadString ``)

**Tiering logic (the combination is the filter):**
- fetch alone → informational (admin `iwr -OutFile` is benign and common)
- fetch **+** run-in-memory (the cradle) → medium ← *this is the real detection*
- cradle **+** (encoding **or** hidden window **or** suspicious parent) → high

Keep fetch / run / evasion as **separate selections** so the condition can tier them — don't OR all three into one
flat `contains` list, or you throw away the structure that makes the rule precise.

---

## Data Source Research

### Sysmon EID 1 — Process Creation (Rule A)

| Field | Use |
|---|---|
| `Image` | `...\powershell.exe` or `pwsh.exe` |
| `CommandLine` | full command — cleartext fetch primitives + evasion flags |
| `ParentImage` | launch context (one level only — see lineage note) |
| `ProcessGuid` / `ProcessId` | correlation key for walking ancestry / joining to 4104 |

Suspicious command-line patterns: `-EncodedCommand`, `-nop`, `-w hidden`, `IEX`, `DownloadString`
(note: only visible here when **not** encoded).

### WinEvent EID 4104 — PowerShell Script Block Logging (Rule B)

4104 logs the text of each script block **as the engine compiles it to run it.** That mechanic explains both its
strength and its limits.

**What it defeats:**
- `-EncodedCommand <base64>` — the engine **must** decode the base64 into a script before running, and that
  decoded block is logged. Cleartext intent (`DownloadString` etc.) reappears even when EID 1 only saw base64.
  → this is 4104's headline strength and the whole reason it gets its own rule.
- `IEX (decoded string)` — the string handed to IEX becomes a **new** script block, also logged. Multi-layer
  obfuscation tends to **peel across successive 4104 events** as each layer invokes the next.

**What it does NOT do:**
4104 is **not** a deobfuscator. It logs what the engine compiles, not a cleaned/normalised version. Inline source
obfuscation that resolves only at evaluation — string concat (`'Down'+'loadString'`), char-code arrays, backtick
insertion (`` D`o`wnloadString ``) — is logged **literally as written**, and only becomes cleartext if the result
is re-invoked through `IEX` / `&` / `[ScriptBlock]::Create`. So a naive `ScriptBlockText|contains: 'DownloadString'`
is beaten by `'Download'+'String'`. → put this in Blind Spots.

**Key fields:**
- `ScriptBlockText` — the executed PowerShell code (the core field).
- `ScriptBlockId` — GUID; correlates related entries (e.g. a block split across multiple events).
- `Path` — file path if run from a file (empty for interactive / in-memory).
- `HostApplication` — the launching process/command line (e.g. `powershell.exe -enc ...`) — useful even when the
  body is obfuscated.
- `MessageNumber` / `MessageTotal` — flags when one block is split across multiple log entries (reassemble before matching).


---

## Existing Community Rules Reviewed

> Review download-cradle prior art in the **two folders that mirror my two-rule split**:
> `rules/windows/process_creation/` and `rules/windows/powershell/powershell_script/` (+ `powershell_classic/`).
> Use a rule search frontend (e.g. sigmaquery.com / detection.fyi) to filter by technique × logsource rather than
> hand-walking the tree. Remember: `test` status is normal/healthy, not "deprecated" — most good rules sit at `test`.

| Source | Rule | Notes |
|---|---|---|
| SigmaHQ `powershell_classic/posh_pc_download_via_webclient.yml` | Download via Net.WebClient | Scans WebClient downloads; common second-stage pull. Read for field usage on the 4104 side. |
| SigmaHQ `process_creation/proc_creation_win_powershell_download_cradle_obfuscated.yml` | Obfuscated one-liners | Short, but the obfuscated-cradle concept is directly relevant. EID 1 side. |
| SigmaHQ `powershell_script/posh_ps_remote_session_creation.yml` | Remote session creation | Adjacent (not download) — keep for reference only. |

**Takeaway so far:** community rules are mostly *one simple rule per primitive*. They're a **baseline, not a
deliverable** — Sigma is a *distribution* format (portable, lowest-common-denominator, no env dependencies), so
the env-specific tuning, baselining and correlation are the value *I* add on top. My contribution is the tiering +
the two-layer design + the correlation, not re-deriving a WebClient keyword match.

---

## Potential Evasion Paths (→ Blind Spots section)

1. **Parent image workarounds**
   - Legit-looking parent + encoded command to masquerade.
   - **Intermediary hop** — `<dodgy> → cmd.exe → powershell.exe` defeats single-level parent matching.
     Mitigation: walk lineage (ProcessGuid chain / MDE parent field).
   - **PPID spoofing** (`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`) — the recorded parent can be *forged*. Can't fully
     solve at this layer; rely on the **content signal (Rule B / 4104)**, which doesn't depend on a trustworthy parent.
     → this is the argument for why the two rules aren't redundant.
2. **EID 1 encoding** — `-enc` hides intent on the command line. Rule A flags the *flag*; Rule B recovers the
   *content*. The two are correlated in the platform for a holistic view.
3. **4104 evasion** — v2 downgrade (no 4104 at all); inline source obfuscation not normalised by 4104
   (concat/charcode/backtick) — see 4104 notes.

---

## Hardening Recommendations (NOT part of the detection — keep separate)

> Prevention ≠ detection. These belong under Response / hardening in the writeup, not in the detection logic.

- Remove PowerShell/CMD execution from non-IT/security users via RBAC — restricts shell usage for users who don't
  need it for BAU, and mitigates many shell-reliant TTPs at once.
- Constrained Language Mode, AppLocker/WDAC, and `-version 2` blocking (to close the 4104 downgrade bypass).
