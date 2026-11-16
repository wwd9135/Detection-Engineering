"""Run Gitleaks over PR commits, push commits, or full history for manual runs."""

import argparse
import os
import re
import subprocess
from pathlib import Path

from scripts.ci.common import annotation, summary

ZERO_SHA = "0" * 40


def git(*args):
    return subprocess.check_output(["git", *args], text=True).strip()


def valid_sha(value):
    if not re.fullmatch(r"[0-9a-fA-F]{40}", value):
        raise ValueError("Expected a full Git commit SHA from the event payload")
    git("cat-file", "-e", f"{value}^{{commit}}")
    return value


def scan_range(event, base="", head="", before=""):
    if event == "pull_request":
        base, head = valid_sha(base), valid_sha(head)
        merge_base = git("merge-base", base, head)
        return f"{merge_base}..{head}"
    if event == "push":
        head = valid_sha(head)
        if before and before != ZERO_SHA:
            # fetch-depth: 0 normally supplies this commit. A force-push may
            # orphan it; scan all reachable history rather than silently skip.
            try:
                return f"{valid_sha(before)}..{head}"
            except subprocess.CalledProcessError:
                return head
        return head
    return "--all"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gitleaks", default="gitleaks")
    parser.add_argument("--event", default=os.environ.get("SCAN_EVENT", "workflow_dispatch"))
    parser.add_argument("--base", default=os.environ.get("SCAN_BASE", ""))
    parser.add_argument("--head", default=os.environ.get("SCAN_HEAD", ""))
    parser.add_argument("--before", default=os.environ.get("SCAN_BEFORE", ""))
    parser.add_argument("--config", type=Path, default=Path(".gitleaks.toml"))
    args = parser.parse_args(argv)
    try:
        revisions = scan_range(args.event, args.base, args.head, args.before)
        # Scan every introduced commit, including secrets added then removed in
        # the same PR. No path filter: rules, tests, config and docs are covered.
        command = [args.gitleaks, "git", ".", "--redact=100", "--no-banner", "--verbose",
                   "--config", str(args.config), "--ignore-gitleaks-allow",
                   f"--log-opts=--full-history --diff-merges=first-parent {revisions}"]
        result = subprocess.run(command, check=False)
        summary("Secret scanning", [
            f"Gitleaks scanned commit range `{revisions}` with full secret redaction.",
            "No secrets found." if result.returncode == 0 else
            "Scan failed or secrets were found. Review the redacted job log; this check blocks merging.",
        ])
        return result.returncode
    except Exception as error:
        annotation("error", f"Secret scanning could not complete: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
