import json
from pathlib import Path

import pytest

from scripts.ci.attack import build_index, main, validate_tags
from scripts.ci.common import Rule, load_rules


def technique(identifier="T1053.005", **extra):
    return {"type": "attack-pattern", "id": f"attack-pattern--{identifier}",
            "name": identifier, "external_references": [
                {"source_name": "mitre-attack", "external_id": identifier}], **extra}


@pytest.fixture
def bundle():
    return {"type": "bundle", "objects": [
        technique(), technique("T1053"), technique("T9998", revoked=True),
        technique("T9997", x_mitre_deprecated=True),
        {"type": "x-mitre-tactic", "id": "x-mitre-tactic--test",
         "name": "Persistence", "x_mitre_shortname": "persistence",
         "external_references": [{"source_name": "mitre-attack", "external_id": "TA0003"}]},
    ]}


def errors(tags, bundle):
    return validate_tags(Rule(Path("rule.yml"), {"tags": tags}), *build_index(bundle))


@pytest.mark.parametrize("tags", [
    ["attack.persistence", "attack.t1053.005"],
    ["attack.TA0003", "attack.T1053"],
    ["attack.persistence", "attack.t1053", "attack.t1053.005", "detection.test"],
])
def test_valid_tags(tags, bundle):
    assert errors(tags, bundle) == []


@pytest.mark.parametrize("tag", [
    "attack.t1053.999", "attack.t1053.05", "attack.t9999", "attack.persistance",
    "attack.t9998", "attack.t9997", "attack.t1053.005.extra", "attack.unknown",
])
def test_unknown_malformed_and_retired_tags_fail(tag, bundle):
    assert errors(["attack.persistence", "attack.t1053.005", tag], bundle)


@pytest.mark.parametrize("tags", [[], ["attack.persistence"], ["attack.t1053"], "attack.t1053", [None]])
def test_missing_or_invalid_tags_fail(tags, bundle):
    assert errors(tags, bundle)


def test_newest_stix_revision_wins(bundle):
    bundle["objects"] += [technique(modified="2026-01-01", revoked=True),
                           technique(modified="2025-01-01")]
    assert "revoked" in errors(["attack.persistence", "attack.t1053.005"], bundle)[0]


@pytest.mark.parametrize("bundle", [{}, {"type": "bundle", "objects": []}])
def test_unusable_bundle_fails(bundle):
    with pytest.raises(ValueError):
        build_index(bundle)


def test_empty_rule_directory_fails(tmp_path):
    with pytest.raises(ValueError, match="No Sigma rules"):
        load_rules(tmp_path)


def test_rule_discovery_ignores_auxiliary_yaml_and_reads_multiple_documents(tmp_path):
    (tmp_path / "scapy.yml").write_text(">>> not yaml", encoding="utf-8")
    (tmp_path / "rule.yaml").write_text(
        "detection: {condition: a, a: {EventID: 1}}\nlogsource: {product: windows}\n"
        "---\ndetection: {condition: b, b: {EventID: 2}}\nlogsource: {product: windows}\n",
        encoding="utf-8")
    assert [rule.document for rule in load_rules(tmp_path)] == [1, 2]


def test_cli_blocks_invalid_mapping(tmp_path, bundle, capsys):
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
    (tmp_path / "rule.yml").write_text(
        "tags: [attack.persistence, attack.t9999]\n"
        "logsource: {product: windows}\ndetection: {a: {EventID: 1}, condition: a}\n",
        encoding="utf-8")
    assert main([str(tmp_path), "--bundle", str(bundle_path)]) == 1
    assert "::error file=" in capsys.readouterr().out


def test_cli_fails_closed_on_bad_bundle(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("not json", encoding="utf-8")
    assert main([str(tmp_path), "--bundle", str(path)]) == 1
