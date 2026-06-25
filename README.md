# Detection Engineering Portfolio

Early-career security engineer building and validating detections in Microsoft Sentinel (KQL), Corelight NDR, and Microsoft Defender — authored in Sigma as the source of truth and tested against a personal home lab.

---

## Coverage Summary

> **ATT&CK Navigator layer** — see [coverage/](coverage/) for the JSON layer file.
> Screenshot placeholder: replace with an exported image from [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) once you have enough rules to visualise.

| Tactic | Techniques Covered |
|---|---|
| Persistence | T1547.001 |
| *(more to come)* | |

---

## Repo Navigation

```
.
├── README.md               ← you are here
├── docs/                   ← methodology, templates, conventions
├── detections/             ← Sigma rules + KQL, grouped by ATT&CK tactic
├── tuning/                 ← before/after tuning writeups
├── coverage/               ← ATT&CK Navigator layer
├── lab/                    ← home-lab architecture notes
├── .github/workflows/      ← CI: sigma check + compile
└── requirements.txt        ← Python toolchain
```

| Folder | Purpose |
|---|---|
| [docs/](docs/) | Detection methodology, ADS template, naming conventions, tuning template |
| [detections/](detections/) | One sub-folder per tactic; each detection has a `rule.yml`, `rule.kql`, `README.md`, and validation notes |
| [tuning/](tuning/) | Noise-reduction work: problem → hypothesis → before/after logic → metrics |
| [emulation/](emulation/) | Test procedures per technique; maps to Atomic Red Team test numbers where applicable |
| [coverage/](coverage/) | ATT&CK Navigator JSON layer tracking what is and isn't covered |
| [lab/](lab/) | Synthetic home-lab topology used for validation (no production data) |

---

## Detection Methodology

See [docs/methodology.md](docs/methodology.md) for the full write-up. The short version:

> **Hypothesis → Research → Rule → Validate → Tune → Metrics**

Every detection in this repo started as a threat-behaviour hypothesis, was grounded in ATT&CK, authored in Sigma, validated by generating the behaviour in a home lab, and then tuned based on observed false-positive rates.

---

## Toolchain

- **Rule authoring**: [Sigma](https://github.com/SigmaHQ/sigma) (YAML)
- **Validation / compile**: [sigma-cli](https://github.com/SigmaHQ/sigma-cli) + [pySigma](https://github.com/SigmaHQ/pySigma) with the Microsoft Sentinel / Kusto backend
- **Primary SIEM target**: Microsoft Sentinel (KQL / `DeviceRegistryEvents`, `DeviceProcessEvents`, etc.)
- **NDR**: Corelight (Zeek logs)
- **Framework**: MITRE ATT&CK

```bash
# Install toolchain
pip install -r requirements.txt

# Validate all rules
sigma check detections/

# Compile a single rule to KQL
sigma convert -t kusto -p microsoft_xdr detections/persistence/T1547.001-registry-run-keys/rule.yml
```

---

## Conventions

See [docs/naming-conventions.md](docs/naming-conventions.md) for the full standard. TL;DR:

- Detection folders: `{TECHNIQUE-ID}-{short-slug}` e.g. `T1547.001-registry-run-keys`
- Sigma rule `id` field: stable UUID, never reused
- Every rule carries `attack.persistence` (tactic) **and** `attack.t1547.001` (technique) tags
- Compiled KQL lives next to the rule as `rule.kql` — regenerate with sigma-cli, commit both

---

## Disclaimer

All rules, log samples, and test evidence in this repo were generated in a personal home lab on equipment I own. No employer data, no production systems, no real internal hostnames or IP addresses appear anywhere in this repository.
