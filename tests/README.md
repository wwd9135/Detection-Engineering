# Detection Test Infrastructure

## How it works

Every detection rule in `detections/` can be paired with two frozen EVTX
captures. On every push CI runs Chainsaw against those captures and asserts:

- `test_fires_on_malicious` — the rule gets **≥ 1 hit** on the attack sample
- `test_quiet_on_benign` — the rule gets **0 hits** on the benign sample

If either assertion fails the build goes red before the change can be merged.

---

## Directory layout

```
tests/
├── fixtures/
│   └── <TECHNIQUE-ID>/          # folder name is exactly the technique ID
│       ├── malicious.evtx       # attack behaviour — rule MUST fire
│       └── benign.evtx          # normal/near-miss activity — rule MUST stay quiet
├── mappings/
│   └── sigma-event-logs-all.yml # NOT committed — extracted from Chainsaw tarball by CI
├── fixtures/readme.md           # per-technique capture notes
├── test_detections.py           # pytest harness
└── README.md                    # this file
```

---

## How the harness pairs fixtures to rules

`discover()` in `test_detections.py` iterates every folder under `tests/fixtures/`
and globs for a matching rule:

```
tests/fixtures/T1059.001/  →  detections/**/T1059.001-*/rule.yml
```

Detection folders are named `<TECHNIQUE-ID>-<slug>` so one fixture folder
covers all rules sharing that technique ID.

**Case matters on Linux.** The rule file must be named `rule.yml` (all
lowercase). Windows hides case mismatches; CI on Ubuntu does not.

---

## GitHub Actions workflow

File: `.github/workflows/Sigma_Lint.yml`

| Job | What it does | Blocks merge? |
|---|---|---|
| `lint` | `sigma check detections/` — validates rule syntax | Yes |
| `compile-test` | `sigma convert` to KQL — catches backend issues | No (`continue-on-error`) |
| `test-detections` | Chainsaw + pytest against EVTX fixtures | Yes |

**Triggers:** any push or PR touching `detections/**`, `tests/**`,
`requirements.txt`, or the workflow file itself.

The `test-detections` job installs Chainsaw from the latest GitHub release and
extracts `sigma-event-logs-all.yml` from the tarball at run time — that mapping
file is not committed to the repo.

---

## Adding a new detection to the test suite

### 1. Know your rule's logsource

Open `rule.yml` and read the `logsource` block. That tells you which Windows
log channel to capture from.

| logsource | Channel to export |
|---|---|
| `category: powershell` | `Microsoft-Windows-PowerShell/Operational` |
| `category: process_creation` (Sysmon) | `Microsoft-Windows-Sysmon/Operational` |
| `category: registry_set` (Sysmon) | `Microsoft-Windows-Sysmon/Operational` |
| `product: windows, service: security` | `Security` |

Check the Sigma logsource documentation if your rule uses something else.

### 2. Prepare a Windows lab machine

Use a VM or dedicated test host — never a shared or production machine.
`wevtutil cl` clears the entire channel.

For PowerShell rules, enable Script Block Logging first (required for EID 4104):
```powershell
# Run as Administrator — one-time setup
$p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $p -Force | Out-Null
Set-ItemProperty -Path $p -Name EnableScriptBlockLogging -Value 1 -Type DWord
```

### 3. Capture `malicious.evtx`

```powershell
# Replace the channel with the one your rule targets
$channel = "Microsoft-Windows-PowerShell/Operational"

# 1. Clear — keeps the export small and unambiguous
wevtutil cl $channel

# 2. Run ONLY the malicious activity your rule is supposed to detect
#    (see the per-technique notes in tests/fixtures/readme.md)

# 3. Export
wevtutil epl $channel tests\fixtures\<TECHNIQUE-ID>\malicious.evtx
```

Verify the export is a real EVTX binary (it starts with the bytes `ElfFile`
and is at least ~65 KB for even one event):
```powershell
(Get-Item tests\fixtures\<TECHNIQUE-ID>\malicious.evtx).Length
```

### 4. Capture `benign.evtx`

```powershell
# 1. Clear again
wevtutil cl $channel

# 2. Run NEAR-MISS activity — things that look similar to the attack but
#    should be suppressed by your rule's filters/exclusions.
#    Unrelated noise proves nothing; near-misses actually test your exclusions.

# 3. Export
wevtutil epl $channel tests\fixtures\<TECHNIQUE-ID>\benign.evtx
```

### 5. Commit

```powershell
git add tests/fixtures/<TECHNIQUE-ID>/
git commit -m "test: add EVTX fixtures for <TECHNIQUE-ID>"
git push
```

CI triggers automatically because `tests/**` is in the path filter.

---

## Debugging a failing test locally

Run Chainsaw directly to see the raw match output:

```powershell
chainsaw hunt tests\fixtures\<TECHNIQUE-ID>\malicious.evtx `
  --sigma "detections\<category>\<TECHNIQUE-ID>-<slug>\rule.yml" `
  --mapping tests\mappings\sigma-event-logs-all.yml `
  --json | ConvertFrom-Json | ConvertTo-Json -Depth 10
```

The output shows the exact event fields that matched. If `test_quiet_on_benign`
fails, run the same command against `benign.evtx` to find the false-positive event,
then add a filter to the rule to exclude it.

---

## Common pitfalls

| Symptom | Cause | Fix |
|---|---|---|
| `T1234.567-NO-RULE` in test id | `rule.yml` has capital letters or doesn't exist in git | Check `git ls-files detections/` and that the filename is lowercase `rule.yml` |
| `NOTSET SKIPPED` — zero tests collected | `tests/fixtures/` has no subdirectories in git | Commit the fixture folder (git won't track empty dirs) |
| `failed to deserialize evtx stream` | File is not a real EVTX binary (too small, or a text file with wrong extension) | Recapture with `wevtutil epl` |
| Rule fires on benign sample | Detection condition is too broad or fixture contains near-miss that exposes a gap in your filters | Read the Chainsaw JSON output to find the offending event, then tune the rule |
| Works locally, fails in CI | Filename case mismatch (`Rule.yml` vs `rule.yml`) — Windows hides it, Linux doesn't | `git mv Rule.yml rule.yml.tmp && git mv rule.yml.tmp rule.yml` |
