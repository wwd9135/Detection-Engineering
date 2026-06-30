# Detection Test Fixtures

Each detection with event-level tests gets a folder here named **exactly** after
its detection folder, containing two frozen Windows Event Log exports:

```
tests/fixtures/
└── T1547.001-registry-run-keys/
    ├── malicious.evtx   # contains the attack behaviour — rule MUST fire
    └── benign.evtx      # benign + near-miss activity — rule MUST stay quiet
```

`tests/test_detections.py` discovers these automatically. Adding a detection to
CI is **data-only**: drop in a fixture pair whose folder name matches the
detection folder, commit. No code changes.

---

## Which channel do I capture from?

The channel is **per rule** — read the rule's `logsource`. For the registry
example the relevant telemetry is **Sysmon Event ID 13** on the
`Microsoft-Windows-Sysmon/Operational` channel (NOT PowerShell). A future
PowerShell rule would capture `Microsoft-Windows-PowerShell/Operational`, a
process rule Sysmon EID 1, and so on.

> ⚠️ `wevtutil cl` clears the **entire** channel. Lab machines only — never a
> shared or production host. Clearing first keeps the export tiny and the test
> focused. All fixtures are synthetic/lab data, same as the rest of this repo
> (see the root README disclaimer).

---

## Capturing `malicious.evtx`

```powershell
# 1. Clear the channel so the export is small and contains only this test
wevtutil cl "Microsoft-Windows-Sysmon/Operational"

# 2. Generate ONLY the malicious behaviour
Invoke-AtomicTest T1547.001 -TestNumbers 1
#    -> reg.exe writes HKCU\...\Run\AtomicTest  (Sysmon EID 13)

# 3. Export the channel to the fixture
wevtutil epl "Microsoft-Windows-Sysmon/Operational" `
  tests\fixtures\T1547.001-registry-run-keys\malicious.evtx

# 4. Clean up the registry change
Invoke-AtomicTest T1547.001 -TestNumbers 1 -Cleanup
```

## Capturing `benign.evtx` (the one that earns its keep)

A benign fixture full of unrelated noise proves nothing — your rule was never
going to fire on it. The benign fixture must contain the **near-misses**: the
activity that *looks* like the attack but is legitimate, so the test actually
exercises your exclusions. For this rule that means a `msiexec.exe` run-key
write, which `filter_system_processes` is supposed to suppress (this is exactly
the scenario you already reasoned about in `validation.md §5`).

```powershell
wevtutil cl "Microsoft-Windows-Sysmon/Operational"

# Generate benign run-key activity that hits the exclusion path, e.g. an MSI
# install that writes a Run key, or a manual msiexec-driven write. Optionally
# add a normal installer writing a Run key from its own process.
# ... run legitimate activity here ...

wevtutil epl "Microsoft-Windows-Sysmon/Operational" `
  tests\fixtures\T1547.001-registry-run-keys\benign.evtx
```

---

## Don't regenerate casually

Once committed, a fixture is a **frozen regression baseline**. Recapturing it
(new timestamps/SIDs/process GUIDs) throws away the thing you are
regression-testing against. Only recapture when the telemetry *shape* itself
legitimately changes — e.g. a Sysmon schema change or a different test.

> Tradeoff to be aware of: EVTX is binary, so a reviewer can't eyeball a fixture
> diff in a PR the way they can a rule diff. That's an accepted cost for letting
> Chainsaw read the native format with no conversion step. If reviewability ever
> matters more, evtx_dump to JSONL is the alternative (and would need its own
> `!tests/fixtures/**/*.json` gitignore exception).

---

## .gitignore

The repo ignores `*.evtx`. Add this exception **after** the `*.evtx` line in the
"Log exports / raw telemetry" block so the negation takes effect:

```gitignore
*.evtx
!tests/fixtures/**/*.evtx
```
