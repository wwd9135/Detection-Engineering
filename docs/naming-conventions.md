# Naming Conventions

Consistent naming makes the repo navigable and makes CI filtering simple. These conventions are enforced by the linting workflow.

---

## Detection Folder Names

```
detections/{tactic-slug}/{TECHNIQUE-ID}-{short-slug}/
```

| Part | Rule | Example |
|---|---|---|
| `{tactic-slug}` | Lowercase ATT&CK tactic name, hyphens for spaces | `persistence`, `lateral-movement`, `credential-access` |
| `{TECHNIQUE-ID}` | ATT&CK technique ID in uppercase as defined by MITRE | `T1547.001`, `T1078`, `T1003.001` |
| `{short-slug}` | Lowercase, hyphens, 2–5 words describing the specific behaviour | `registry-run-keys`, `pass-the-hash`, `lsass-dump` |

**Valid examples:**
```
detections/persistence/T1547.001-registry-run-keys/
detections/lateral-movement/T1550.002-pass-the-hash/
detections/credential-access/T1003.001-lsass-memory-dump/
detections/defense-evasion/T1562.001-disable-windows-defender/
```

**Invalid examples:**
```
detections/Persistence/t1547-run-keys/          ← tactic not lowercase, ID not sub-technique
detections/persistence/registry_run_keys/        ← underscores, no technique ID
detections/persistence/runkey/                   ← no technique ID
```

---

## Tactic Folder Names

Use the ATT&CK tactic names verbatim (lowercase, hyphens):

| ATT&CK Tactic | Folder name |
|---|---|
| Initial Access | `initial-access` |
| Execution | `execution` |
| Persistence | `persistence` |
| Privilege Escalation | `privilege-escalation` |
| Defense Evasion | `defense-evasion` |
| Credential Access | `credential-access` |
| Discovery | `discovery` |
| Lateral Movement | `lateral-movement` |
| Collection | `collection` |
| Command and Control | `command-and-control` |
| Exfiltration | `exfiltration` |
| Impact | `impact` |

---

## Sigma Rule Files

| File | Contents |
|---|---|
| `rule.yml` | The authoritative Sigma rule |
| `rule.kql` | Compiled KQL output — regenerate with `sigma convert`, commit alongside |

If a single technique has multiple meaningfully different detection variants (different data sources, different event types), name them:
```
rule-registry.yml / rule-registry.kql
rule-process.yml  / rule-process.kql
```

---

## Sigma Rule Fields

### `title`
`[Platform] [Behaviour description]` — short, scannable.

```yaml
title: Windows Registry Run Key Persistence via Sysmon
```

### `id`
A stable UUID v4. Generate once, never change, never reuse. Generate with:
```bash
python -c "import uuid; print(uuid.uuid4())"
```

### `status`
| Value | Meaning |
|---|---|
| `stable` | Validated in lab, known FP rate, ready for production-like use |
| `experimental` | Written but not yet fully validated |
| `test` | Rule is only for testing the pipeline — do not deploy |
| `deprecated` | Superseded or no longer useful — keep for history |

### `tags`
Always include both the tactic tag and the technique tag:
```yaml
tags:
  - attack.persistence          # tactic
  - attack.t1547.001            # sub-technique (lowercase, dot notation)
```

For techniques with multiple relevant tactics (e.g. privilege escalation and persistence), include all applicable tactic tags.

### `level`
| Value | Meaning in this repo |
|---|---|
| `critical` | High-confidence, low-FP, maps to an active, impactful technique |
| `high` | High-confidence but slightly higher FP rate or lower-impact technique |
| `medium` | Moderate confidence — needs analyst context |
| `low` | High noise / wide detection — useful for hunting, not alerting |
| `informational` | Telemetry visibility check — not a real alert |

---

## File Naming Within a Detection Folder

| File | Required? | Contents |
|---|---|---|
| `rule.yml` | Yes | Sigma rule |
| `rule.kql` | Yes | Compiled KQL (committed, not generated at runtime) |
| `README.md` | Yes | ADS write-up (see `docs/detection-template.md`) |
| `research-notes.md` | Yes | Research trail and source notes |
| `validation.md` | Yes | Test evidence and confirmation the rule fires |
| `assets/` | Optional | Screenshots, PCAP snippets, exported log excerpts (sanitised) |

---

## Tuning Record Folder Names

```
tuning/{short-slug}/
```

The slug should describe the change, not the rule:
```
tuning/example-beacon-fp-reduction/
tuning/run-key-installer-filter/
tuning/lsass-dump-signed-binary-exception/
```

---

## Branch Names (if contributing via PR)

```
{type}/{slug}
```

| Type | Used for |
|---|---|
| `detect/` | New detection rule |
| `tune/` | Tuning update to existing rule |
| `docs/` | Documentation only |
| `ci/` | CI / workflow changes |
| `coverage/` | ATT&CK Navigator layer updates |

Examples: `detect/T1547.001-registry-run-keys`, `tune/run-key-installer-filter`
