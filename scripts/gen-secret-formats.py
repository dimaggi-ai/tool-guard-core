#!/usr/bin/env python3
"""Generate Go secret rules from pinned third_party/gitleaks/gitleaks.toml.

The upstream MIT license is in third_party/gitleaks/LICENSE.
Preserves regex, keyword, entropy, path, and allowlist matching metadata.
Descriptions, title, and minVersion are explicitly ignored presentation metadata.
Only the path-only pkcs12-file rule is excluded from text detection.

Usage:
  python3 scripts/gen-secret-formats.py          rewrite the Go table
  python3 scripts/gen-secret-formats.py --check  fail if the table is stale
  python3 scripts/gen-secret-formats.py --list   list included and excluded IDs

Requires Python 3.11+ and gofmt; no third-party dependencies.
"""
import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
import tomllib

GITLEAKS_COMMIT = "5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c"
ROOT = pathlib.Path(__file__).resolve().parent.parent
RULES = ROOT / "third_party" / "gitleaks" / "gitleaks.toml"
OUTPUT = ROOT / "pkg" / "engine" / "secret_rules_generated.go"
EXCLUDED = {"pkcs12-file": "path-only rule; text detection requires a regex"}
TOP_FIELDS = {"title", "minVersion", "allowlist", "allowlists", "rules"}
RULE_FIELDS = {"id", "description", "regex", "keywords", "secretGroup", "entropy", "path", "allowlist", "allowlists"}
ALLOWLIST_FIELDS = {"description", "condition", "regexTarget", "regexes", "stopwords", "paths"}


def fields(value: dict, known: set[str], context: str) -> None:
    if not isinstance(value, dict):
        raise ValueError(f"{context}: expected a table")
    unknown = value.keys() - known
    if unknown:
        raise ValueError(f"{context}: unsupported fields: {', '.join(sorted(unknown))}")


def string(value: object, context: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{context}: expected a string")
    return value


def strings(value: object, context: str) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"{context}: expected a string array")
    return [string(item, context) for item in value]


def allowlists(value: dict, context: str) -> list[dict]:
    if "allowlist" in value and "allowlists" in value:
        raise ValueError(f"{context}: simultaneous allowlist and allowlists are unsupported")
    entries = [value["allowlist"]] if "allowlist" in value else value.get("allowlists", [])
    if not isinstance(entries, list):
        raise ValueError(f"{context}.allowlists: expected an array of tables")
    for i, entry in enumerate(entries):
        label = f"{context}.allowlists[{i}]"
        fields(entry, ALLOWLIST_FIELDS, label)
        if "description" in entry:
            string(entry["description"], label + ".description")
        condition = string(entry.get("condition", ""), label + ".condition")
        if condition.upper() not in ("", "AND", "OR", "&&", "||"):
            raise ValueError(f"{label}: unsupported condition {condition!r}")
        target = string(entry.get("regexTarget", ""), label + ".regexTarget")
        if target not in ("", "secret", "match", "line"):
            raise ValueError(f"{label}: unsupported regexTarget {target!r}")
        for key in ("regexes", "stopwords", "paths"):
            strings(entry.get(key, []), label + "." + key)
    return entries


def load() -> tuple[list[dict], list[dict]]:
    data = tomllib.loads(RULES.read_text(encoding="utf-8"))
    fields(data, TOP_FIELDS, "config")
    for key in ("title", "minVersion"):
        if key in data:
            string(data[key], "config." + key)
    global_allowlists = allowlists(data, "config")
    if not isinstance(data.get("rules"), list):
        raise ValueError("config.rules: expected an array of tables")
    result, seen, excluded = [], set(), set()
    for rule in data["rules"]:
        fields(rule, RULE_FIELDS, "rule")
        rid = string(rule.get("id"), "rule.id")
        if not rid or rid in seen:
            raise ValueError(f"empty or duplicate rule ID: {rid!r}")
        seen.add(rid)
        if "description" in rule:
            string(rule["description"], rid + ".description")
        strings(rule.get("keywords", []), rid + ".keywords")
        string(rule.get("path", ""), rid + ".path")
        group = rule.get("secretGroup", 0)
        if type(group) is not int or group < 0:
            raise ValueError(f"{rid}.secretGroup: expected a nonnegative integer")
        entropy = rule.get("entropy", 0)
        if type(entropy) not in (int, float) or not 0 <= entropy < float("inf"):
            raise ValueError(f"{rid}.entropy: expected a finite nonnegative number")
        allowlists(rule, rid)
        if rid in EXCLUDED:
            if "regex" in rule or not rule.get("path"):
                raise ValueError(f"{rid}: excluded path-only rule changed semantics")
            excluded.add(rid)
            continue
        if not string(rule.get("regex"), rid + ".regex"):
            raise ValueError(f"{rid}: empty regex")
        result.append(rule)
    if excluded != EXCLUDED.keys():
        raise ValueError("excluded rules changed; review EXCLUDED")
    return result, global_allowlists


def quote(value: str) -> str:
    # Upstream allowlists contain full example credentials. Concatenated small
    # chunks preserve values without storing complete credential literals.
    chunks = [value[i:i + 16] for i in range(0, len(value), 16)] or [""]
    return " + ".join(json.dumps(chunk, ensure_ascii=True) for chunk in chunks)


def array(values: list[str]) -> str:
    return "[]string{" + ", ".join(quote(value) for value in values) + "}"


def render_allowlists(entries: list[dict], indent: str) -> list[str]:
    lines = []
    for entry in entries:
        lines.append(indent + "{")
        for key, go_key in (("condition", "Condition"), ("regexTarget", "RegexTarget")):
            if key in entry:
                value = entry[key]
                if key == "condition":
                    value = {"&&": "AND", "||": "OR"}.get(value, value.upper())
                lines.append(indent + "\t" + go_key + ": " + quote(value) + ",")
        for key, go_key in (("regexes", "Regexes"), ("stopwords", "Stopwords"), ("paths", "Paths")):
            if key in entry:
                lines.append(indent + "\t" + go_key + ": " + array(entry[key]) + ",")
        lines.append(indent + "},")
    return lines


def render(rules: list[dict], global_allowlists: list[dict]) -> str:
    lines = [
        "// Code generated by scripts/gen-secret-formats.py; DO NOT EDIT.",
        "// Source: third_party/gitleaks/gitleaks.toml (MIT).",
        "// Upstream commit: " + GITLEAKS_COMMIT,
        "// Source SHA256: " + hashlib.sha256(RULES.read_bytes()).hexdigest(),
        "", "package engine", "", "var secretRules = []secretRule{",
    ]
    for rule in rules:
        lines.extend([
            "\t{", "\t\tID: " + quote(rule["id"]) + ",",
            "\t\tPattern: " + quote(rule["regex"]) + ",",
            "\t\tKeywords: " + array(rule.get("keywords", [])) + ",",
            "\t\tSecretGroup: " + str(rule.get("secretGroup", 0)) + ",",
            "\t\tEntropy: " + repr(rule.get("entropy", 0)) + ",",
        ])
        if "path" in rule:
            lines.append("\t\tPath: " + quote(rule["path"]) + ",")
        entries = allowlists(rule, rule["id"])
        if entries:
            lines.append("\t\tAllowlists: []secretAllowlist{")
            lines.extend(render_allowlists(entries, "\t\t\t"))
            lines.append("\t\t},")
        lines.append("\t},")
    lines.extend(["}", "", "var secretGlobalAllowlists = []secretAllowlist{"])
    lines.extend(render_allowlists(global_allowlists, "\t"))
    lines.extend(["}", "", "var secretExcludedRules = map[string]string{"])
    lines.extend("\t" + quote(rid) + ": " + quote(reason) + "," for rid, reason in sorted(EXCLUDED.items()))
    lines.extend(["}", ""])
    formatted = subprocess.run(
        ["gofmt"], input="\n".join(lines), text=True, capture_output=True,
        check=True, timeout=15,
    )
    return formatted.stdout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--list", action="store_true")
    args = parser.parse_args()
    try:
        rules, global_allowlists = load()
        if args.list:
            for rule in rules:
                print(rule["id"])
            for rid, reason in sorted(EXCLUDED.items()):
                print(f"excluded: {rid}: {reason}")
            return 0
        new = render(rules, global_allowlists)
        if args.check:
            old = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else None
            if new != old:
                print("stale: run python3 scripts/gen-secret-formats.py", file=sys.stderr)
                return 1
        else:
            OUTPUT.write_text(new, encoding="utf-8")
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        print(f"secret rule generation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
