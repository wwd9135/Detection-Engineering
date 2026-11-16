"""Fail on unknown, revoked, deprecated, or malformed Enterprise ATT&CK tags."""

import argparse
import hashlib
import json
import re
from pathlib import Path
from urllib.request import urlopen

from scripts.ci.common import annotation, load_rules, summary

ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
TECHNIQUE = re.compile(r"t\d{4}(?:\.\d{3})?", re.IGNORECASE)


def build_index(bundle):
    if bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
        raise ValueError("ATT&CK data must be a STIX bundle with objects")
    # In a bundle containing historical revisions, only the newest revision counts.
    latest = {}
    for obj in bundle["objects"]:
        if obj.get("type") not in {"attack-pattern", "x-mitre-tactic"}:
            continue
        key = obj["id"]
        if key not in latest or obj.get("modified", "") > latest[key].get("modified", ""):
            latest[key] = obj
    techniques, tactics = {}, {}
    for obj in latest.values():
        target = techniques if obj["type"] == "attack-pattern" else tactics
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                target[ref["external_id"].lower()] = obj
        if obj["type"] == "x-mitre-tactic" and obj.get("x_mitre_shortname"):
            tactics[obj["x_mitre_shortname"].lower()] = obj
    if not techniques or not tactics:
        raise ValueError("ATT&CK bundle has no techniques or tactics; refusing to pass")
    return techniques, tactics


def validate_tags(rule, techniques, tactics):
    tags = rule.data.get("tags", [])
    if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
        return ["tags must be a list of strings"]
    errors = []
    found_technique = found_tactic = False
    for tag in tags:
        if not tag.lower().startswith("attack."):
            continue
        value = tag[7:].lower()
        if TECHNIQUE.fullmatch(value):
            found_technique = True
            entry = techniques.get(value)
        else:
            entry = tactics.get(value)
            found_tactic |= entry is not None
        if entry is None:
            errors.append(f"{tag}: unknown or malformed Enterprise ATT&CK technique/tactic")
        elif entry.get("revoked") or entry.get("x_mitre_deprecated"):
            status = "revoked" if entry.get("revoked") else "deprecated"
            errors.append(f"{tag}: {status} ATT&CK entry ({entry.get('name', value)})")
    if not found_technique:
        errors.append("missing attack.tNNNN[.NNN] technique tag")
    if not found_tactic:
        errors.append("missing current ATT&CK tactic tag (for example attack.persistence)")
    return errors


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rules", nargs="?", type=Path, default=Path("detections"))
    parser.add_argument("--bundle", type=Path, help="Use a local STIX bundle for offline checks")
    args = parser.parse_args(argv)
    try:
        if args.bundle:
            raw = args.bundle.read_bytes()
        else:
            with urlopen(ATTACK_URL, timeout=60) as response:
                raw = response.read()
        bundle = json.loads(raw)
        techniques, tactics = build_index(bundle)
        rules = load_rules(args.rules)
        failures = []
        for rule in rules:
            for error in validate_tags(rule, techniques, tactics):
                message = f"{rule.label}: {error}"
                annotation("error", message, rule.path)
                failures.append(message)
        summary("MITRE ATT&CK mappings", [
            f"Checked {len(rules)} rule(s); {len(failures)} error(s).",
            f"Source: {args.bundle or ATTACK_URL}",
            f"Bundle SHA-256: `{hashlib.sha256(raw).hexdigest()}`",
            *[f"- {error}" for error in failures],
        ])
        return int(bool(failures))
    except Exception as error:
        annotation("error", f"ATT&CK validation could not complete: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
