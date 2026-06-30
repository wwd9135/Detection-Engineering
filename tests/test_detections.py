"""
Event-level regression tests for the detection portfolio.

For every detection that has a fixture pair under tests/fixtures/<name>/,
run its Sigma rule against both fixtures with Chainsaw and assert:
  - it FIRES on malicious.evtx   (the rule still catches the behaviour)
  - it stays QUIET on benign.evtx (no false positive / over-broad match)

WHY THIS SCALES
---------------
The machinery here is written once. Adding a new detection to CI is a
DATA-ONLY change: drop a folder under tests/fixtures/ whose name matches the
detection's folder name under detections/, containing malicious.evtx and
benign.evtx. No edits to this file. discover() finds the new pair and pytest
parametrizes a test for it automatically, with the folder name as the test id.

Place this file at: tests/test_detections.py
"""
import json
import pathlib
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
# v2 ships this mapping; copy it from the Chainsaw release into tests/mappings/.
MAPPING = ROOT / "tests" / "mappings" / "sigma-event-logs-all.yml"


def discover():
    """Pair each fixture folder with its detection rule.yml, by folder name.

    A fixture folder named 'T1547.001-registry-run-keys' is matched to
    detections/**/T1547.001-registry-run-keys/rule.yml. The names must match.
    """
    cases = []
    if not FIXTURES.exists():
        return cases
    for fix_dir in sorted(p for p in FIXTURES.iterdir() if p.is_dir()):
        rule = next(ROOT.glob(f"detections/**/{fix_dir.name}/rule.yml"), None)
        if rule is None:
            # A fixture with no matching rule is a wiring bug, not a pass.
            cases.append(
                pytest.param(None, fix_dir, id=f"{fix_dir.name}-MISSING-RULE")
            )
        else:
            cases.append(pytest.param(rule, fix_dir, id=fix_dir.name))
    return cases


CASES = discover()


def chainsaw_hits(rule: pathlib.Path, evtx: pathlib.Path) -> int:
    """Run ONE Sigma rule against ONE evtx file and return the match count.

    Loading a single rule via --sigma means only that rule can match, so the
    returned count is a clean proxy for "did this rule fire".
    """
    proc = subprocess.run(
        [
            "chainsaw", "hunt", str(evtx),
            "--sigma", str(rule),
            "--mapping", str(MAPPING),
            "--json", "--no-banner",
        ],
        capture_output=True,
        text=True,
    )

    # CRITICAL: a non-zero exit means Chainsaw itself failed (bad mapping,
    # unreadable evtx, a rule it couldn't convert). If we skipped this check,
    # empty stdout would parse as zero hits and the benign test would pass
    # green while proving nothing. Fail loudly instead.
    assert proc.returncode == 0, (
        f"chainsaw exited {proc.returncode} for {rule.name} on {evtx.name}:\n"
        f"{proc.stderr.strip()}"
    )

    out = proc.stdout.strip()
    # With --no-banner + --json, stdout should be a JSON array. Tolerate a
    # stray leading info line by slicing from the first '['. If your pinned
    # Chainsaw version writes JSON elsewhere, switch to `-o <file>` and read it.
    start = out.find("[")
    data = json.loads(out[start:]) if start != -1 else []
    return len(data)


@pytest.mark.parametrize("rule,fixtures", CASES)
def test_fires_on_malicious(rule, fixtures):
    assert rule is not None, (
        f"No detections/**/{fixtures.name}/rule.yml found for this fixture"
    )
    hits = chainsaw_hits(rule, fixtures / "malicious.evtx")
    assert hits >= 1, (
        f"{fixtures.name}: rule MISSED its malicious sample "
        f"(likely the rule logic OR the Chainsaw mapping)"
    )


@pytest.mark.parametrize("rule,fixtures", CASES)
def test_quiet_on_benign(rule, fixtures):
    assert rule is not None, (
        f"No detections/**/{fixtures.name}/rule.yml found for this fixture"
    )
    hits = chainsaw_hits(rule, fixtures / "benign.evtx")
    assert hits == 0, (
        f"{fixtures.name}: rule FIRED on benign sample ({hits} hit(s)) — "
        f"possible false positive / over-broad match / weakened exclusion"
    )