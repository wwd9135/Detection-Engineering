"""Advisory duplicate and redundant-condition checks for Sigma rules."""

import argparse
import itertools
import re
from collections import defaultdict
from pathlib import Path

from sigma.conditions import ConditionAND, ConditionIdentifier, ConditionNOT, ConditionOR, ConditionSelector
from sigma.rule import SigmaDetections

from scripts.ci.common import annotation, encode, load_rules, stable, summary


def group(operator, children):
    """Normalize commutative operators, including nesting and repeated operands."""
    flattened = []
    for child in children:
        flattened.extend(child[1:] if child[0] == operator else [child])
    unique = sorted(set(flattened), key=repr)
    return unique[0] if len(unique) == 1 else (operator, *unique)


def condition_tree(node, detections, repetitions=None):
    if isinstance(node, ConditionIdentifier):
        if node.identifier not in detections.detections:
            raise ValueError(f"Unknown condition selector: {node.identifier}")
        return ("selection", node.identifier)
    if isinstance(node, ConditionSelector):
        children = node.resolve_referenced_detections(detections)
        if not children:
            raise ValueError(f"Selector matches nothing: {node.pattern}")
        operator = "and" if node.cond_class is ConditionAND else "or"
        return group(operator, [condition_tree(child, detections, repetitions) for child in children])
    if isinstance(node, ConditionNOT):
        return ("not", condition_tree(node.args[0], detections, repetitions))
    if isinstance(node, (ConditionAND, ConditionOR)):
        operator = "and" if isinstance(node, ConditionAND) else "or"
        children = [condition_tree(child, detections, repetitions) for child in node.args]
        operands = [item for child in children
                    for item in (child[1:] if child[0] == operator else [child])]
        if repetitions is not None and len(set(operands)) != len(operands):
            repetitions.append(f"Repeated Boolean operand in '{operator}' condition")
        return group(operator, children)
    raise ValueError(f"Unsupported condition node: {type(node).__name__}")


def replace_selections(tree, transform):
    if tree[0] == "selection":
        return ("selection", transform(tree[1]))
    children = [replace_selections(child, transform) for child in tree[1:]]
    return ("not", *children) if tree[0] == "not" else group(tree[0], children)


def leaves(tree):
    if tree[0] == "selection":
        return {tree[1]}
    return set().union(*(leaves(child) for child in tree[1:]))


def evaluate(tree, values):
    if tree[0] == "selection":
        return values[tree[1]]
    if tree[0] == "not":
        return not evaluate(tree[1], values)
    results = (evaluate(child, values) for child in tree[1:])
    return all(results) if tree[0] == "and" else any(results)


def field_shape(value):
    if isinstance(value, dict):
        return {key: field_shape(item) for key, item in value.items()}
    if isinstance(value, list):
        return {"list": sorted({encode(field_shape(item)) for item in value})}
    return type(value).__name__


def features(value, prefix=()):
    """Field/modifier + literal pairs; never compare titles or descriptions."""
    if isinstance(value, dict):
        return set().union(*(features(item, (*prefix, key)) for key, item in value.items()))
    if isinstance(value, list):
        return set().union(*(features(item, prefix) for item in value))
    return {encode([prefix, value])}


def repeated_values(value):
    if isinstance(value, dict):
        return any(repeated_values(item) for item in value.values())
    if isinstance(value, list):
        return len(value) != len({encode(stable(item)) for item in value}) or any(
            repeated_values(item) for item in value)
    return False


class Analysis:
    def __init__(self, rule):
        self.rule = rule
        detection = rule.data["detection"]
        parsed = SigmaDetections.from_dict(detection)
        self.selections = {key: value for key, value in detection.items()
                           if key not in {"condition", "timeframe"}}
        self.repetitions = []
        self.tree = group("or", [condition_tree(cond.parse(False), parsed, self.repetitions)
                                 for cond in parsed.parsed_condition])
        self.payloads = {key: encode(stable(value)) for key, value in self.selections.items()}
        self.logic = replace_selections(self.tree, self.payloads.__getitem__)
        self.shape = replace_selections(self.tree, lambda key: encode(field_shape(self.selections[key])))
        self.context = encode(stable([rule.data["logsource"], detection.get("timeframe")]))
        self.signature = (self.context, self.logic)
        self.features = set().union(*(features(self.selections[key]) for key in leaves(self.tree)))
        self.techniques = {tag.lower() for tag in rule.data.get("tags", [])
                           if isinstance(tag, str) and re.fullmatch(r"attack\.t\d{4}(?:\.\d{3})?", tag, re.I)}

    def redundancies(self):
        messages = list(self.repetitions)
        used = leaves(self.tree)
        for name in self.selections.keys() - used:
            messages.append(f"Unused selection '{name}' cannot affect the condition")
        equivalent = defaultdict(list)
        for name, payload in self.payloads.items():
            equivalent[payload].append(name)
            if repeated_values(self.selections[name]):
                messages.append(f"Selection '{name}' contains repeated values/branches")
        for names in equivalent.values():
            if len(names) > 1:
                messages.append(f"Identical selections cannot fire independently: {', '.join(sorted(names))}")
        variables = sorted(leaves(self.logic))
        if len(variables) > 12:
            messages.append("Boolean redundancy analysis skipped: more than 12 distinct selections")
            return messages
        results = []
        for bits in itertools.product((False, True), repeat=len(variables)):
            results.append(evaluate(self.logic, dict(zip(variables, bits))))
        if not any(results):
            messages.append("Condition can never fire (Boolean contradiction)")
        elif all(results):
            messages.append("Condition is always true (Boolean tautology)")
        else:
            for index, payload in enumerate(variables):
                mask = 1 << (len(variables) - index - 1)
                if all(result == results[row ^ mask] for row, result in enumerate(results)):
                    messages.append("Redundant selection cannot independently affect the result: "
                                    + ", ".join(sorted(equivalent[payload])))
        return messages


def find_overlaps(rules, threshold=0.8):
    analyses = [Analysis(rule) for rule in rules]
    findings = []
    for analysis in analyses:
        findings.extend((analysis.rule, message) for message in analysis.redundancies())
    for left, right in itertools.combinations(analyses, 2):
        other = right.rule.label
        if left.rule.data.get("id") and left.rule.data.get("id") == right.rule.data.get("id"):
            findings.append((left.rule, f"Duplicate rule UUID also used by {other}"))
        if left.signature == right.signature:
            findings.append((left.rule, f"Exact duplicate detection logic: {other}"))
        elif (left.context == right.context and left.techniques & right.techniques
              and left.shape == right.shape):
            union = left.features | right.features
            similarity = len(left.features & right.features) / len(union) if union else 0
            if similarity >= threshold:
                findings.append((left.rule, f"Near-duplicate ({similarity:.0%} field/value overlap): {other}"))
    return findings


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rules", nargs="?", type=Path, default=Path("detections"))
    parser.add_argument("--threshold", type=float, default=0.8)
    args = parser.parse_args(argv)
    if not 0 <= args.threshold <= 1:
        parser.error("--threshold must be between 0 and 1")
    try:
        rules = load_rules(args.rules)
        findings = find_overlaps(rules, args.threshold)
        for rule, message in findings:
            annotation("warning", f"{rule.label}: {message}", rule.path)
        summary("Duplicate and redundant rules (advisory)", [
            f"Checked {len(rules)} rule(s); {len(findings)} warning(s). Findings do not fail this job.",
            *[f"- `{rule.label}`: {message}" for rule, message in findings],
        ])
        return 0
    except Exception as error:
        annotation("error", f"Overlap analysis could not complete: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
