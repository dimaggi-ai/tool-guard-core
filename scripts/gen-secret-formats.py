#!/usr/bin/env python3
"""Generate the gitleaks provider-format conditions in
policies/coding_agent_secret_commands.yaml.

Source: third_party/gitleaks/gitleaks.toml, the default rule file of gitleaks
(MIT licence, third_party/gitleaks/LICENSE) at the commit in GITLEAKS_COMMIT.

The policy uses two layers for provider keys:

- &providerKey, a hand-written regex for the most common prefixes. It is not
  generated.
- One generated condition per scanned field (&gitleaksCommand,
  &gitleaksContent, &gitleaksNewString, &gitleaksEdits). Each condition is an
  "or" with one branch per selected gitleaks rule:
  and: [ <contains guard>, <rule regex> ].

A guard is a literal string that every match of the rule contains, spelled
exactly as in the regex. The engine checks the guard with a substring test
and runs the regex only when the guard is present. This is the gitleaks
keyword prefilter. One alternation of all rules without guards was measured
at 51 ms for a 4 KB text; the guarded form takes under 1 ms.

A rule is selected only when its regex is case-sensitive (no "(?i"),
because a "contains" test is case-sensitive. TestSecretFormatGuards in
cmd/tg proves for every branch that each regex match contains one of the
guards.

The policy engine cannot apply three parts of a gitleaks rule:

- entropy: there is no entropy operator, so a rule matches without the
  randomness check, and placeholder keys such as ghp_xxxx... are recorded;
- allowlists and stopwords: they test the captured secret, and a policy regex
  has no capture step;
- path rules: a rule with a "path" applies to all files here.

EXCLUDED lists the rules that other rules in the policy handle with a
different effect, or that are too broad without entropy.

Usage:
  python3 scripts/gen-secret-formats.py          rewrite the policy
  python3 scripts/gen-secret-formats.py --check  exit 1 if the policy is stale
  python3 scripts/gen-secret-formats.py --list   print the selected rule IDs
"""
import json
import pathlib
import re
import sys
import tomllib

GITLEAKS_COMMIT = "5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c"
ROOT = pathlib.Path(__file__).resolve().parent.parent
RULES = ROOT / "third_party" / "gitleaks" / "gitleaks.toml"
POLICY = ROOT / "policies" / "coding_agent_secret_commands.yaml"

EXCLUDED = {
    # An access key ID is an identifier, not the secret: rule-aws-key-id-in-command flags it.
    "aws-access-token": "flagged by rule-aws-key-id-in-command",
    "yandex-aws-access-token": "key ID shape, same reason as aws-access-token",
    # A JWT may be a public key: rule-jwt-in-command escalates it.
    "jwt": "escalated by rule-jwt-in-command",
    "jwt-base64": "escalated by rule-jwt-in-command",
    # Matches any key=value with a long value; gitleaks needs entropy 3.5 to keep it usable.
    "generic-api-key": "too broad without entropy",
    # Its allowlist drops "$VAR" and placeholder passwords; a policy regex cannot
    # apply it. rule-inline-password covers curl -u with that exclusion.
    "curl-auth-user": "needs its allowlist; rule-inline-password covers it",
    # rule-auth-header covers literal Authorization and API-key headers.
    "curl-auth-header": "covered by rule-auth-header",
    # One branch matches any 40-hex string, such as a git commit SHA.
    "sourcegraph-access-token": "bare 40-hex branch",
}

# Guards for rules whose gitleaks keyword is not spelled literally in the
# regex. Each value must be a literal that every match contains;
# TestSecretFormatGuards checks this.
GUARD_OVERRIDE = {
    "airtable-personnal-access-token": ["pat"],
    # The "." in the regex is not escaped, so "hooks.slack.com" is not a literal.
    "slack-webhook-url": ["hooks"],
    # The keyword is lowercase; the regex requires an uppercase Q.
    "azure-ad-client-secret": ["Q~"],
}

# Each generated line has this form; the anchor names the scanned field.
FIELDS = {
    "gitleaksCommand": "parameters.command",
    "gitleaksContent": "parameters.content",
    "gitleaksNewString": "parameters.new_string",
    "gitleaksEdits": "parameters.edits",
}
LINE = re.compile(r"^(\s*- )&(gitleaks[A-Za-z]+) .*$", re.M)
PLAIN = re.compile(r"[A-Za-z0-9_\-]+")


def spelled(rx: str, keyword: str) -> list[str]:
    """Return each spelling of keyword in the regex source that is plain text."""
    out = []
    low = rx.lower()
    k = keyword.lower()
    i = low.find(k)
    while i >= 0:
        s = rx[i : i + len(k)]
        before = rx[i - 1] if i > 0 else ""
        if PLAIN.fullmatch(s) and before != "\\" and s not in out:
            out.append(s)
        i = low.find(k, i + 1)
    return out


def select() -> list[dict]:
    data = tomllib.loads(RULES.read_text())
    rules = []
    for rule in data["rules"]:
        rid = rule["id"]
        rx = rule.get("regex")
        if rid in EXCLUDED or rx is None or "(?i" in rx:
            continue
        guards = GUARD_OVERRIDE.get(rid)
        if guards is None:
            guards = []
            for kw in rule.get("keywords", []):
                # Prefer the spelling in the regex; otherwise use the keyword
                # as written. TestSecretFormatGuards rejects a wrong guard.
                for g in spelled(rx, kw) or [kw]:
                    if g not in guards:
                        guards.append(g)
        if not guards:
            continue
        rules.append({"id": rid, "regex": rx, "guards": guards})
    return rules


def condition(field: str, rules: list[dict]) -> str:
    branches = []
    for r in rules:
        guard = [{"field": field, "operator": "contains", "value": g} for g in r["guards"]]
        guard_cond = guard[0] if len(guard) == 1 else {"or": guard}
        branches.append({"and": [guard_cond, {"field": field, "operator": "regex", "value": r["regex"]}]})
    # JSON is valid YAML flow syntax; one line per field keeps the diff small.
    return json.dumps({"or": branches}, ensure_ascii=True, separators=(", ", ": "))


def render(policy_text: str) -> str:
    rules = select()
    found = LINE.findall(policy_text)
    if sorted(name for _, name in found) != sorted(FIELDS):
        sys.exit("expected one '- &<name> ...' line for each of " + ", ".join(sorted(FIELDS)))
    return LINE.sub(lambda m: m.group(1) + "&" + m.group(2) + " " + condition(FIELDS[m.group(2)], rules), policy_text)


def main() -> int:
    if "--list" in sys.argv[1:]:
        for r in select():
            print(r["id"], r["guards"])
        return 0
    old = POLICY.read_text()
    new = render(old)
    if "--check" in sys.argv[1:]:
        if new != old:
            print("stale: run python3 scripts/gen-secret-formats.py", file=sys.stderr)
            return 1
        return 0
    POLICY.write_text(new)
    return 0


if __name__ == "__main__":
    sys.exit(main())
