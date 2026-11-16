"""Shared rule discovery and GitHub Actions reporting."""

import json
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Rule:
    path: Path
    data: dict
    document: int = 1

    @property
    def label(self):
        return f"{self.path.as_posix()} (document {self.document})"


def load_rules(root: Path):
    """Read rule.yml/rule.yaml, following the repository's folder-per-rule convention."""
    import yaml

    rules = []
    for path in sorted(set(root.rglob("rule.yml")) | set(root.rglob("rule.yaml"))):
        documents = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
        for index, data in enumerate(documents, 1):
            if not isinstance(data, dict):
                raise ValueError(f"{path}: expected a rule mapping")
            if not isinstance(data.get("detection"), dict) or not isinstance(data.get("logsource"), dict):
                raise ValueError(f"{path}: expected detection and logsource mappings")
            rules.append(Rule(path, data, index))
    if not rules:
        raise ValueError(f"No Sigma rules found in {root}")
    return rules


def annotation(level, message, path=None):
    def escape(value):
        return str(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")

    location = ""
    if path is not None:
        location = " file=" + escape(Path(path).as_posix()).replace(",", "%2C").replace(":", "%3A")
    print(f"::{level}{location}::{escape(message)}")


def summary(title, lines):
    content = f"## {title}\n\n" + "\n".join(lines) + "\n"
    print(content)
    if destination := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(destination, "a", encoding="utf-8") as stream:
            stream.write(content)


def stable(value):
    """Canonical YAML values; Sigma maps and value lists are order-independent."""
    if isinstance(value, dict):
        return {key: stable(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return sorted((stable(item) for item in value), key=encode)
    return value


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
