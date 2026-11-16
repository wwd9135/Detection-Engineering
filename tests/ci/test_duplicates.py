from pathlib import Path

import pytest
import yaml

from scripts.ci.common import Rule
from scripts.ci.duplicates import Analysis, find_overlaps, main


def rule(name="one", condition="selection", selections=None, technique="attack.t1053.005",
         category="process_creation"):
    return Rule(Path(name) / "rule.yml", {
        "title": name, "id": name, "tags": ["attack.persistence", technique],
        "logsource": {"product": "windows", "category": category},
        "detection": {**(selections or {"selection": {"Image|endswith": "\\cmd.exe"}}),
                      "condition": condition},
    })


def messages(*rules):
    return [message for _, message in find_overlaps(list(rules))]


def test_exact_duplicates_ignore_metadata_selection_names_and_order():
    left = rule(condition="a and b", selections={"a": {"EventID": 1},
                "b": {"Image|endswith": ["a.exe", "b.exe"]}})
    right = rule("two", "y and x", {"x": {"EventID": 1},
                 "y": {"Image|endswith": ["b.exe", "a.exe"]}}, technique="attack.t1059.001")
    assert any("Exact duplicate" in message for message in messages(left, right))


def test_wildcard_and_condition_list_equivalence():
    left = rule(condition="1 of sel_*", selections={"sel_a": {"A": 1}, "sel_b": {"B": 2}})
    right = rule("two", ["x", "y"], {"x": {"A": 1}, "y": {"B": 2}})
    assert any("Exact duplicate" in message for message in messages(left, right))


def test_all_of_them_and_not_preserve_semantics():
    left = rule(condition="all of them", selections={"a": {"A": 1}, "b": {"B": 2}})
    right = rule("two", "a and not b", {"a": {"A": 1}, "b": {"B": 2}})
    assert not messages(left, right)


def test_near_duplicates_require_same_technique_logsource_and_condition():
    left = rule(selections={"selection": {"CommandLine|contains": list("abcdefghij")}})
    right = rule("two", selections={"selection": {"CommandLine|contains": list("abcdefghiX")}})
    assert any("Near-duplicate" in message for message in messages(left, right))
    right.data["tags"] = ["attack.t1059.001"]
    assert not messages(left, right)
    right.data["tags"] = left.data["tags"]
    right.data["logsource"]["category"] = "registry_set"
    assert not messages(left, right)
    right.data["logsource"] = left.data["logsource"]
    right.data["detection"]["condition"] = "not selection"
    assert not messages(left, right)


def test_shared_technique_alone_does_not_mean_duplicate():
    assert not messages(rule(), rule("two", selections={"selection": {"EventID": 13}}))


@pytest.mark.parametrize("condition, expected", [
    ("a or (a and b)", "Redundant selection"),
    ("a and not a", "can never fire"),
    ("a or not a", "always true"),
    ("a", "Unused selection 'b'"),
])
def test_boolean_redundancies(condition, expected):
    result = Analysis(rule(condition=condition, selections={"a": {"A": 1}, "b": {"B": 2}}))
    assert any(expected in message for message in result.redundancies())


def test_identical_selectors_cannot_fire_independently():
    result = Analysis(rule(condition="a and not b", selections={"a": {"A": 1}, "b": {"A": 1}}))
    assert any("Identical selections" in item for item in result.redundancies())
    assert any("can never fire" in item for item in result.redundancies())


@pytest.mark.parametrize("condition", ["a or a", "a and (b and a)"])
def test_repeated_boolean_operands(condition):
    result = Analysis(rule(condition=condition, selections={"a": {"A": 1}, "b": {"B": 2}}))
    assert any("Repeated Boolean operand" in item for item in result.redundancies())


def test_repeated_values_and_duplicate_ids():
    left = rule(selections={"selection": {"A": [1, 1]}})
    right = rule("two")
    right.data["id"] = left.data["id"]
    assert any("repeated values" in item for item in messages(left, right))
    assert any("Duplicate rule UUID" in item for item in messages(left, right))


def test_large_boolean_analysis_is_reported():
    result = Analysis(rule(condition="all of them", selections={f"s{i}": {"A": i} for i in range(13)}))
    assert any("skipped" in item for item in result.redundancies())


@pytest.mark.parametrize("condition", ["unknown", "1 of missing_*", "a and ("])
def test_invalid_conditions_fail(condition):
    with pytest.raises(Exception):
        Analysis(rule(condition=condition))


def test_warnings_do_not_fail_cli(tmp_path, capsys):
    data = rule(condition="a or (a and b)", selections={"a": {"A": 1}, "b": {"B": 2}}).data
    (tmp_path / "rule.yml").write_text(yaml.safe_dump(data), encoding="utf-8")
    assert main([str(tmp_path)]) == 0
    assert "::warning file=" in capsys.readouterr().out
