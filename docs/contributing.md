# Contributing detections

Keep Sigma source in `detections/<tactic>/<TECHNIQUE-ID>-<slug>/rule.yml`
(or `rule.yaml`). Both extensions and multiple YAML rule documents are checked
by the ATT&CK and overlap validators. Auxiliary YAML such as `scapy.yml` is not
treated as a Sigma rule by these validators. Keep the generated SIEM query and
validation evidence alongside the rule.

## Run the new checks locally

Use Python 3.11 from the repository root:

```bash
python -m pip install -r requirements-ci.txt
python -m pytest tests/ci/ -v
python -m scripts.ci.attack
python -m scripts.ci.duplicates
```

These dependencies are separate from `requirements.txt`, which supplies the
existing Sigma lint/conversion jobs. The ATT&CK and overlap jobs run independently
of lint. The Chainsaw job runs only the EVTX harness; the ATT&CK job runs the CI
validator regression tests. Secret-scanner integration tests also run in the
secret-scanning job after Gitleaks is installed.

## ATT&CK mapping failures

Each rule must have at least one technique tag, such as `attack.t1053.005`, and
at least one tactic tag, such as `attack.persistence`. Parent techniques
(`attack.t1053`) and tactic IDs (`attack.ta0003`) are also supported. Tags outside
the `attack.` namespace are ignored. Every `attack.` tag must resolve to a
technique or tactic in Enterprise ATT&CK.

The validator downloads MITRE's [current Enterprise ATT&CK STIX bundle](https://github.com/mitre-attack/attack-stix-data)
on every run. It rejects unknown/malformed IDs, outdated tactic names, revoked
entries, and entries marked `x_mitre_deprecated`. A renamed technique that keeps
its active ID remains valid: the rule tags reference IDs rather than titles.
This validates existence and lifecycle status, not whether the detection's
behavior is correctly mapped to that technique or tactic.

Failures identify the rule and offending tag. Update the mapping after checking
MITRE's replacement guidance; do not simply delete the tag to make CI pass.
Download/parse failures fail the job instead of reusing stale cached data. The
summary records the source and SHA-256 of the bundle used for that run. For
offline reproduction, save that bundle and run:

```bash
python -m scripts.ci.attack --bundle /path/to/enterprise-attack.json
```

## Duplicate and redundant-rule warnings

The overlap job emits file-linked warnings and a job summary for:

- Exact detection duplicates after ignoring metadata and normalizing selector
  names, map/list order, commutative Boolean operands, and wildcard selectors.
  Logsource and timeframe must match; sharing a technique is not required.
- Near-duplicates with the same logsource/timeframe, at least one identical
  technique tag, equivalent condition/field structure, and at least 80% Jaccard
  similarity of field/modifier/value pairs. Titles and descriptions do not
  influence similarity. Use `--threshold 0.9` locally to adjust the threshold.
- Reused rule UUIDs, identical selections, repeated Boolean operands/values, unused selections,
  Boolean contradictions/tautologies, and selections absorbed by other branches
  (for example `a or (a and b)`, where `b` cannot change the result).

Review each warning. Merge truly redundant rules, remove dead conditions, or
explain intentional overlap in the PR. Rules sharing a technique but monitoring
different logs or behavior are legitimate. Existing rules are included so a new
rule can be compared with the whole portfolio.

Findings do not fail the job. Invalid input or analyzer errors do fail it so
the job cannot silently skip review. This is a conservative heuristic, not a
proof of semantic equivalence: it does not infer implications between regexes,
substrings, or field constraints, or reason about event correlation. Boolean
analysis treats distinct selections as independent variables, merges identical
ones, and is limited to 12 distinct selections to bound runtime; a skipped
analysis is reported. Pairwise duplicate/similarity checks still run.

## Secret-scanning failures

CI downloads the official [Gitleaks v8.30.1 binary](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1)
and verifies its pinned SHA-256 before execution. It uses the built-in provider
token/private-key rules and additional quoted/unquoted password rules in
[.gitleaks.toml](../.gitleaks.toml). All output is fully redacted; no findings
artifact containing secret values is uploaded. The scanner requires no API
credentials and also runs on fork PRs with a read-only repository token.

For PRs, checkout includes full history and the scanner checks
`merge-base(base, head)..head`. It scans the patches of **every introduced
commit**, including merge resolutions and secrets added then removed before the
final commit. Commits exclusive to the base branch are excluded. No file path
filter is applied: rules, test fixtures, configuration, and docs are included.
For pushes it checks `before..head`; new branches and pushes whose old tip is no
longer available scan all history reachable from the new tip. Manual runs scan
all fetched history. Missing PR revisions or scanner failures fail the job.

With Gitleaks installed, reproduce a PR scan using full commit SHAs:

```bash
python -m scripts.ci.secrets --event pull_request --base <BASE_SHA> --head <HEAD_SHA>
# Full-history audit:
python -m scripts.ci.secrets
```

The CLI must run in a Git checkout with the required commits available. By
default it uses `gitleaks` on PATH; use `--gitleaks /path/to/gitleaks` to override
the binary. Gitleaks integration tests run when it is available on PATH or via
the `GITLEAKS_BIN` environment variable.

Replace leaked values with environment references or explicit placeholders. If
a real credential was committed, revoke/rotate it and remove it from the PR's
introduced history before rerunning CI; deleting it in a later commit is
insufficient. Document any narrowly justified false-positive exclusion in the
PR. Do not add broad path exclusions. Inline `gitleaks:allow` bypass comments
are disabled by the scanner command.

Gitleaks detects credential patterns; it does not guarantee that arbitrary
personal information or sensitive binary telemetry will be detected. Continue
sanitizing lab evidence before committing it.

## Required checks

The workflow has six jobs on every push/PR/manual run. Configure GitHub branch
protection or a repository ruleset to require the displayed checks for Sigma
validation, Chainsaw, ATT&CK mapping, and secret scanning. Duplicate findings
and the existing KQL conversion job are advisory. Workflow failure by itself
does not configure repository merge protection.
