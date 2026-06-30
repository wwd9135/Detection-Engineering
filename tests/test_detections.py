"""
Event-level regression tests for the detection portfolio.

Each detection with tests gets a fixture folder named by its ATT&CK technique
ID, containing two frozen event-log exports:

    tests/fixtures/
    └── T1059.001/
        ├── malicious.evtx   # rule MUST fire
        └── benign.evtx      # rule MUST stay quiet

The folder name (e.g. T1059.001) is matched to its detection by prefix, since
detection folders are named {TECHNIQUE-ID}-{slug}:

    tests/fixtures/T1059.001/  ->  detections/**/T1059.001-*/rule.yml

Adding a detection to the suite is DATA-ONLY: create tests/fixtures/<ID>/ with
the two evtx files and commit. No edits to this file. Every fixture folder is
tested on every run — nothing is swapped in or out.

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
    """Pair each fixture folder (named by technique ID) with its rule.yml."""
    cases = []
    if not FIXTURES.exists():
        return cases
    for fix_dir in sorted(p for p in FIXTURES.iterdir() if p.is_dir()):
        tech_id = fix_dir.name  # e.g. "T1059.001"
        # Detection folders are named {TECHNIQUE-ID}-{slug}, so match on prefix.
        matches = sorted(
            set(ROOT.glob(f"detections/**/{tech_id}-*/rule.yml"))
            | set(ROOT.glob(f"detections/**/{tech_id}/rule.yml"))
        )
        if not matches:
            # A fixture with no matching detection is a wiring bug, not a pass.
            cases.append(pytest.param(None, fix_dir, id=f"{tech_id}-NO-RULE"))
            continue
        for rule in matches:
            # Detection folder name as the test id keeps output readable and
            # distinguishes multiple rules that share one technique.
            cases.append(pytest.param(rule, fix_dir, id=rule.parent.name))
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

    # A non-zero exit means Chainsaw itself failed (bad mapping, unreadable
    # evtx, a rule it couldn't convert). Without this check, empty stdout would
    # parse as zero hits and the benign test would pass green while proving
    # nothing. Fail loudly instead.
    assert proc.returncode == 0, (
        f"chainsaw exited {proc.returncode} for {rule.name} on {evtx.name}:\n"
        f"{proc.stderr.strip()}"
    )

    out = proc.stdout.strip()
    start = out.find("[")
    data = json.loads(out[start:]) if start != -1 else []
    return len(data)


@pytest.mark.parametrize("rule,fixtures", CASES)
def test_fires_on_malicious(rule, fixtures):
    assert rule is not None, (
        f"No detections/**/{fixtures.name}-*/rule.yml found for this fixture"
    )
    hits = chainsaw_hits(rule, fixtures / "malicious.evtx")
    assert hits >= 1, (
        f"{fixtures.name}: rule MISSED its malicious sample "
        f"(likely the rule logic OR the Chainsaw mapping)"
    )


@pytest.mark.parametrize("rule,fixtures", CASES)
def test_quiet_on_benign(rule, fixtures):
    assert rule is not None, (
        f"No detections/**/{fixtures.name}-*/rule.yml found for this fixture"
    )
    hits = chainsaw_hits(rule, fixtures / "benign.evtx")
    assert hits == 0, (
        f"{fixtures.name}: rule FIRED on benign sample ({hits} hit(s)) — "
        f"possible false positive / over-broad match / weakened exclusion"
    )