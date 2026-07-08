# Expand CI: add MITRE ATT&CK validation, duplicate-rule detection, and secret scanning

## Summary

Our GitHub Actions pipeline currently runs three jobs. This issue proposes adding **at least three more** to catch mapping errors, redundant rules, and leaked secrets before they merge.

## Current jobs

1. Sigma syntax check
2. Sigma → KQL conversion check
3. Chainsaw batch unit testing

## Proposed new jobs

### 1. MITRE ATT&CK mapping check

Validate that every TTP tag referenced in a rule actually exists in MITRE ATT&CK.

- Parse technique/sub-technique IDs (e.g. `T1053.005`) and tactic tags from each rule.
- Fail the check on any ID that isn't a valid, current ATT&CK entry (catches typos and deprecated/renamed techniques).
- _Possible tooling:_ `mitreattack-python` or the ATT&CK STIX bundle.

### 2. Duplicate & redundant rule detection

Flag rules that overlap so we don't ship two detections for the same behaviour.

- Detect exact duplicates and near-duplicates (same technique + substantially similar logic).
- Surface redundant conditions *within* a single rule (e.g. signals that can never fire independently).
- Report as warnings for review rather than a hard fail, at least initially.

### 3. Secret scanning

Scan the diff for credentials and sensitive data leakage.

- API keys/tokens, passwords, private keys, and other information leakage in rules, tests, or config.
- _Possible tooling:_ `gitleaks` or `trufflehog`, ideally on the PR diff.

## Acceptance criteria

- [ ] MITRE ATT&CK mapping check runs on every PR and fails on invalid TTP tags.
- [ ] Duplicate/redundant-rule detection runs and reports overlaps.
- [ ] Secret scanning runs on the PR diff and blocks on findings.
- [ ] New jobs are documented in the repo README / contributing guide.
