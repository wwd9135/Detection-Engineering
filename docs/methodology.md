# Detection Methodology

This document describes the end-to-end process I follow for every detection in this portfolio. The goal is a repeatable, evidence-backed workflow that produces detections I can defend — not just rules that exist on paper.

---

## The Process at a Glance

```
Hypothesis → Research → Rule → Validate → Tune → Metrics
```

---

## 1. Hypothesis

Every detection starts with a question:

> *"If an adversary were doing X in my environment, what observable artefact would they leave behind?"*

Hypotheses come from a few sources:

- **ATT&CK technique review** — reading the technique page, the procedure examples, and the referenced malware/threat-actor reports.
- **Threat intelligence** — public reporting on campaigns relevant to the environment (Windows endpoints, Active Directory, cloud).
- **Red team / purple team output** — findings from emulation exercises that weren't detected.
- **Incident retrospectives** — "we caught this one manually; can we automate it?"

The hypothesis should be falsifiable: I should be able to describe a test that would confirm or deny whether the detection works.

---

## 2. Research

Before writing a single line of YAML, I spend time understanding the attack:

1. **Read the ATT&CK page** — tactic, technique, sub-technique, procedure examples, mitigations, and detection guidance.
2. **Find public PoC / tooling** — understand what real implementations look like (e.g. Metasploit modules, Atomic Red Team tests, open-source offensive tooling).
3. **Map to data sources** — which telemetry actually captures the behaviour? (Sysmon, Windows Security event log, Defender for Endpoint `DeviceProcessEvents`, Corelight `dns.log`, etc.)
4. **Check existing community rules** — SigmaHQ rules, Elastic detection rules, Chronicle YARA-L. I don't copy them; I read them to understand what fields and logic others have found effective, then write my own.
5. **Note evasion paths** — what would break this detection? Document in the README's "Blind Spots" section so I'm honest about coverage.

Research notes go in `research-notes.md` alongside each rule.

---

## 3. Rule Authoring

Rules are written in **Sigma** as the single source of truth.

- **Format**: Sigma YAML, validated with `sigma check`.
- **Structure**: one behaviour per file; if a technique has meaningfully different variants (e.g. process-create vs. registry vs. network), they get separate rule files.
- **Tags**: every rule carries the ATT&CK tactic tag (`attack.persistence`) **and** the technique/sub-technique tag (`attack.t1547.001`).
- **Fields used**: I prefer fields that are stable across log sources (e.g. `CommandLine`, `Image`, `TargetObject`) over raw event field names, relying on Sigma field mappings to translate.
- **Condition logic**: I aim for high-specificity conditions — broad `selection | filter` patterns rather than overly complex nested logic.

After authoring, the rule is compiled to KQL with:

```bash
sigma convert -t kusto -p microsoft_xdr rule.yml
```

The compiled KQL is reviewed for correctness, sometimes hand-tuned for clarity, and committed as `rule.kql`.

---

## 4. Validation

A rule that has never fired against real (or simulated) behaviour is just a hypothesis still.

**Validation steps:**

1. **Emulation** — run the relevant Atomic Red Team test (or a manual equivalent) in the home lab. Document the exact command, the test host, and the timestamp.
2. **Confirm telemetry** — verify the log event that the rule is meant to detect actually appeared in the SIEM.
3. **Confirm the rule fires** — run the Sigma-compiled KQL against the captured telemetry and confirm it returns the emulated event.
4. **Document evidence** — screenshots or log excerpts (sanitised, synthetic) go in `validation.md`. These are placeholders that I replace with real lab evidence as each test is run.

See [emulation/](../emulation/) for test procedures and [detections/{tactic}/{technique}/validation.md](../detections/) for per-rule evidence.

---

## 5. Tuning

Almost every detection produces false positives in practice. The tuning workflow:

1. **Run in observe mode** — deploy the rule in alert-only / non-blocking mode for a period (days to weeks depending on event volume).
2. **Triage FPs** — categorise every non-true-positive: benign software exhibiting the same behaviour, misconfigured baselines, overly broad logic.
3. **Form a hypothesis** — "I think the noise comes from X; if I add filter Y, volume drops by Z% without losing true positives."
4. **Test the filter** — validate that the filter doesn't suppress the emulated TP.
5. **Document** — write the tuning record in `tuning/` (before/after logic, rationale, metrics).

Tuning records live in [tuning/](../tuning/).

---

## 6. Metrics

For each deployed detection I track (informally, in notes):

| Metric | Description |
|---|---|
| Alert volume / week | How noisy is this rule in practice? |
| True positive rate | Of all alerts, how many are real or emulated TPs? |
| False positive rate | How many are noise? |
| Mean time to validate (MTTV) | How long does it take an analyst to close a TP alert? |
| Coverage gaps | What evasion paths remain undetected? |

These numbers feed back into the tuning cycle and inform prioritisation of new detections.

---

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Palantir ADS (Alert & Detection Strategy) Framework](https://github.com/palantir/alerting-detection-strategy-framework)
- [SigmaHQ](https://github.com/SigmaHQ/sigma)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [Detection Maturity Level Model](https://ryanstillions.blogspot.com/2014/04/the-dml-model_21.html)
