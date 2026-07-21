# Detections Index

All detections are grouped by ATT&CK tactic. Each detection folder contains:

| File | Description |
|---|---|
| `rule.yml` | Sigma rule (source of truth) |
| `rule.kql` | Compiled KQL for Microsoft Sentinel |
| `README.md` | ADS write-up (goal, strategy, blind spots, FPs, response) |
| `research-notes.md` | Research trail and source notes |
| `validation.md` | Lab emulation evidence and rule-firing confirmation |
| `assets/` | Screenshots and log excerpts (sanitised) |

See [docs/naming-conventions.md](../docs/naming-conventions.md) for folder and file naming rules.
See [docs/detection-template.md](../docs/detection-template.md) for the ADS README template.

---

## Coverage Table

| Tactic | Technique ID | Sub-technique | Name | Severity | Status |
|---|---|---|---|---|---|
| Persistence | T1547 | .001 | [Registry Run Key Persistence](persistence/T1547.001-registry-run-keys/README.md) | High | Stable |
| Persistence | T1547 | .001 | [Startup Folder Persistence](persistence/T1547.001-Startup-Folder/README.md) | High | Experimental |
| Persistence | T1053 | .005 | [Scheduled task creation](persistence/T1053.005-Scheduled-task-creation/README.md) | High | Experimental |
| Execution   | T1059 | .001 | [PowerShell execution](execution/T1059.001-PowerShell-Execution/README.md) | High | Stable |
| Defence Evasion | T1218 | .005 / .010 / .011 | [System binary proxy execution](defence-evasion/T1218.005-System-Binary-Proxy-Execution/README.md) | Tiered (Medium–Critical) | Experimental |
---

## Adding a New Detection

1. Create the folder: `detections/{tactic}/{TECHNIQUE-ID}-{short-slug}/`
2. Copy `docs/detection-template.md` to `README.md` and fill it in.
3. Author the Sigma rule in `rule.yml` and validate with `sigma check`.
4. Use chainsaw to test batches of logs against your rule
5. Compile to KQL: `sigma convert -t kusto -p microsoft_xdr rule.yml > rule.kql`
6. Test SIEM picks up the threat using Atomic Red Team for live data.
5. Write `research-notes.md` and `validation.md`.
6. Update the coverage table above.
7. Update the ATT&CK Navigator layer in `coverage/`.
