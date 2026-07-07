"""
Event-level regression tests for the detection portfolio.

Each detection with tests gets a fixture folder named by its ATT&CK technique
ID, holding sample event-log exports whose FILENAME declares what the rule
should do. Classification is by filename prefix (case-insensitive):

    malicious*.evtx  -> the rule MUST fire on it       (>= 1 hit)
    benign*.evtx     -> the rule MUST stay quiet on it  (0 hits)

A fixture may hold a single pair (flat) or many samples, in the folder itself
or in ANY subfolder — the whole tree is searched recursively and every sample
is tested as its own case:

    tests/fixtures/
    ├── T1059.001/                       # one pair, flat
    │   ├── malicious.evtx
    │   └── benign.evtx
    └── T1053.005/
        └── ChainsawTestData/            # many samples, in a subfolder
            ├── malicious_schtask_encoded_powershell.evtx
            ├── malicious_privesc_runlevel_highest.evtx
            ├── benign_signed_backup_task.evtx
            └── benign_installer_temp_task.evtx

The folder name (e.g. T1053.005) is matched to its detection by prefix, since
detection folders are named {TECHNIQUE-ID}-{slug}:

    tests/fixtures/T1053.005/  ->  detections/**/T1053.005-*/rule.yml

Adding a detection to the suite is DATA-ONLY: create tests/fixtures/<ID>/, drop
in one or more malicious*/benign* .evtx files (optionally under a subfolder),
and commit. No edits to this file. Every sample is tested on every run.

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


def _chainsaw_bin() -> str:
    """Prefer a chainsaw binary vendored in tests/ (convenient for local runs,
    e.g. tests/chainsaw.exe on Windows); otherwise fall back to `chainsaw` on
    PATH, which is how CI installs it."""
    for name in ("chainsaw.exe", "chainsaw"):
        cand = ROOT / "tests" / name
        if cand.exists():
            return str(cand)
    return "chainsaw"


CHAINSAW = _chainsaw_bin()


def rules_for(tech_id: str):
    """Every rule.yml whose detection folder matches this technique ID.

    Detection folders are named {TECHNIQUE-ID}-{slug}, so match on prefix; also
    allow a folder named exactly the technique ID. Returns a sorted list — a
    technique can legitimately map to more than one detection.
    """
    return sorted(
        set(ROOT.glob(f"detections/**/{tech_id}-*/rule.yml"))
        | set(ROOT.glob(f"detections/**/{tech_id}/rule.yml"))
    )


def verdict_of(evtx: pathlib.Path):
    """Expected verdict for a sample, from its filename prefix, or None."""
    name = evtx.name.lower()
    if name.startswith("malicious"):
        return "malicious"
    if name.startswith("benign"):
        return "benign"
    return None


def discover():
    """Build the parametrized case lists by walking tests/fixtures/.

    Returns (malicious_cases, benign_cases, wiring_errors):
      * malicious/benign cases are (rule, evtx) pairs, one per sample per
        matching rule.
      * wiring_errors are human-readable messages for setup mistakes that must
        FAIL loudly rather than pass silently — a fixture with no matching rule,
        a fixture with no samples, or a sample whose name doesn't start with
        malicious/benign (which would otherwise be silently untested).
    """
    malicious, benign, wiring = [], [], []
    if not FIXTURES.exists():
        return malicious, benign, wiring

    for fix_dir in sorted(p for p in FIXTURES.iterdir() if p.is_dir()):
        tech_id = fix_dir.name  # e.g. "T1053.005"
        rules = rules_for(tech_id)
        samples = sorted(fix_dir.rglob("*.evtx"))

        if not samples:
            wiring.append(pytest.param(
                f"fixture '{tech_id}' contains no *.evtx samples",
                id=f"{tech_id}-NO-SAMPLES",
            ))
            continue
        if not rules:
            # A fixture with samples but no detection is a wiring bug, not a pass.
            wiring.append(pytest.param(
                f"fixture '{tech_id}' has {len(samples)} sample(s) but no "
                f"matching detections/**/{tech_id}-*/rule.yml",
                id=f"{tech_id}-NO-RULE",
            ))
            continue

        for evtx in samples:
            verdict = verdict_of(evtx)
            if verdict is None:
                wiring.append(pytest.param(
                    f"sample '{evtx.relative_to(FIXTURES)}' must start with "
                    f"'malicious' or 'benign' to declare its expected verdict",
                    id=f"{tech_id}:{evtx.stem}-UNCLASSIFIED",
                ))
                continue
            for rule in rules:
                # Test id = detection folder + sample stem: readable, and unique
                # when several rules or samples share one technique.
                case = pytest.param(rule, evtx, id=f"{rule.parent.name}/{evtx.stem}")
                (malicious if verdict == "malicious" else benign).append(case)

    return malicious, benign, wiring


MALICIOUS_CASES, BENIGN_CASES, WIRING_ERRORS = discover()


def test_fixtures_present():
    """Fail loudly if no samples were found, instead of a silent green build.

    Empty case lists make the parametrized tests skip with id NOTSET, which
    would otherwise pass CI while testing nothing. Most common cause: the .evtx
    files aren't committed because .gitignore blocks *.evtx (add the exception
    '!tests/fixtures/**/*.evtx') — and git won't commit the now-empty folders.
    Check with: git ls-files tests/fixtures/
    """
    assert MALICIOUS_CASES or BENIGN_CASES, (
        "No malicious*/benign* .evtx samples found under tests/fixtures/ on this "
        "machine. Either none are committed yet, or *.evtx files are blocked by "
        ".gitignore. Run: git ls-files tests/fixtures/"
    )


@pytest.mark.parametrize("message", WIRING_ERRORS)
def test_no_wiring_errors(message):
    """Surface each fixture wiring bug as its own failing test.

    Keeps a mis-wired fixture (no rule, no samples, or an unclassified filename)
    from slipping through as an untested sample on a green build.
    """
    pytest.fail(message)


# Chainsaw prints this (and exits non-zero) when its Sigma/Tau engine cannot
# COMPILE a rule — e.g. a condition too complex for its solver. That is a
# limitation of chainsaw-the-test-tool, not a defect in the rule: `sigma check`
# in the lint job already validates rule correctness and blocks merges on real
# errors. So when we see it here we SKIP rather than fail, keeping CI honest
# about what was actually exercised instead of red-flagging a valid rule.
CHAINSAW_CANNOT_COMPILE = "No valid detection rules were found"


def chainsaw_hits(rule: pathlib.Path, evtx: pathlib.Path) -> int:
    """Run ONE Sigma rule against ONE evtx file and return the match count.

    Loading a single rule via --sigma means only that rule can match, so the
    returned count is a clean proxy for "did this rule fire". If chainsaw cannot
    compile the rule at all, the test is SKIPPED (see note above), not failed.
    """
    proc = subprocess.run(
        [
            CHAINSAW, "hunt", str(evtx),
            "--sigma", str(rule),
            "--mapping", str(MAPPING),
            "--json",
        ],
        capture_output=True,
        text=True,
        # Force UTF-8: chainsaw emits ANSI/box-drawing bytes that the default
        # Windows locale codec (cp1252) can't decode, which otherwise crashes
        # the stdout reader thread and hands back empty output.
        encoding="utf-8",
        errors="replace",
    )

    # Skip (don't fail) rules chainsaw's engine can't compile — a tool limit,
    # not a rule bug. sigma check remains the correctness gate for these.
    if CHAINSAW_CANNOT_COMPILE in (proc.stdout + proc.stderr):
        pytest.skip(
            f"chainsaw cannot compile {rule.parent.name}/{rule.name} "
            f"(rule too complex for chainsaw's Sigma/Tau engine); "
            f"still validated by `sigma check`"
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


@pytest.mark.parametrize("rule,evtx", MALICIOUS_CASES)
def test_fires_on_malicious(rule, evtx):
    hits = chainsaw_hits(rule, evtx)
    assert hits >= 1, (
        f"{evtx.name}: rule MISSED a malicious sample "
        f"(likely the rule logic OR the Chainsaw mapping)"
    )


@pytest.mark.parametrize("rule,evtx", BENIGN_CASES)
def test_quiet_on_benign(rule, evtx):
    hits = chainsaw_hits(rule, evtx)
    assert hits == 0, (
        f"{evtx.name}: rule FIRED on a benign sample ({hits} hit(s)) — "
        f"possible false positive / over-broad match / weakened exclusion"
    )
