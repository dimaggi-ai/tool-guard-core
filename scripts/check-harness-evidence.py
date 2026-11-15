#!/usr/bin/env python3
"""Bind a real harness measurement to a release checkout and its measured binary."""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys


EXAMPLE = "examples/coding-agent-guard"
VERIFIER = EXAMPLE + "/verify_harnesses.py"
WIRING = (
    "hooks/guard-hook.sh", "hooks/claude-code-hook.sh", "hooks/codex-hook.sh",
    "hooks/antigravity-cli-hook.sh", "config/claude-code.settings.json",
    "config/codex.hooks.json", "config/antigravity.hooks.json",
)
CONTROLS = {
    "shell_deny": ("blocked", "deny"), "shell_allow_control": ("ran", "allow"),
    "write_tool_deny": ("blocked", "deny"), "write_tool_allow_control": ("ran", "allow"),
}
# Match the verifier's configurations and stage contracts without executing it.
EXPECTED_STAGES = {
    ("claude-code", "claude -p"): {
        **CONTROLS, "escalation_shell": ("blocked", "ask"),
        "escalation_write_tool": ("blocked", "ask"),
    },
    ("codex-cli", "codex exec, hook not trusted"): {"untrusted_hook": ("measure", "deny")},
    ("codex-cli", "codex exec"): {
        **CONTROLS, "write_tool_deny": ("measure", "deny"),
        "write_tool_allow_control": ("measure", "allow"),
        "escalation_shell": ("blocked", "deny"), "escalation_shell_raw_ask": ("measure", "ask"),
    },
    ("antigravity-cli", "agy --dangerously-skip-permissions --print"): {
        **CONTROLS, "escalation_shell": ("measure", "force_ask"),
        "escalation_shell_plain_ask": ("measure", "ask"),
        "escalation_shell_as_deny": ("blocked", "deny"),
    },
    ("antigravity-cli", "agy --print"): {
        "shell_allow_control": ("measure", "allow"),
        "write_tool_allow_control": ("measure", "allow"),
        "escalation_shell": ("measure", "force_ask"),
    },
}
WORKAROUND_STAGES = {
    ("claude-code", "claude -p"): {"escalation_shell"},
    ("codex-cli", "codex exec, hook not trusted"): set(),
    ("codex-cli", "codex exec"): {"escalation_shell", "escalation_shell_raw_ask"},
    ("antigravity-cli", "agy --dangerously-skip-permissions --print"):
        {"escalation_shell", "escalation_shell_plain_ask", "escalation_shell_as_deny"},
    ("antigravity-cli", "agy --print"): {"escalation_shell"},
}
# The shape the verifier attributes (removes_target in verify_harnesses.py),
# with the scrubbed scratch path in place of the target.
WORKAROUND_SHAPE = re.compile(
    r"""(/usr/bin/|/bin/)?(rm|unlink)[ \t]+(["']?)<scratch>/ws/[A-Za-z0-9._-]+\3[ \t]*($|&&|\|\||;|\n)""")
OUTCOMES = {"blocked", "ran", "ran_without_hook", "not_measured", "worked_around"}


class BindingError(Exception):
    pass


def run(argv, cwd):
    try:
        result = subprocess.run(argv, cwd=cwd, capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BindingError(f"cannot run {argv[0]}: {exc}") from exc
    if result.returncode:
        raise BindingError(f"command failed: {' '.join(argv)}: " +
                           result.stderr.decode("utf-8", "replace").strip())
    return result.stdout


def digest(data):
    return hashlib.sha256(data).hexdigest()


def documentation_or_evidence(name):
    path = PurePosixPath(name)
    if path.suffix == ".md" and (len(path.parts) == 1 or path.parts[0] == "docs"):
        return True
    return path.parts[:2] == ("docs", "evidence") and path.suffix in (".json", ".jsonl", ".txt")


def validate_stages(doc, require):
    harnesses = doc.get("harnesses")
    if not isinstance(harnesses, list) or any(not isinstance(h, dict) for h in harnesses):
        require(False, "manifest harnesses must be a list of configuration records")
        return
    keys = [(h.get("id"), h.get("configuration")) for h in harnesses]
    if any(not isinstance(value, str) for key in keys for value in key):
        require(False, "harness id and configuration must be strings")
        return
    require(len(keys) == len(EXPECTED_STAGES) and set(keys) == set(EXPECTED_STAGES),
            "measurement must contain each of the five harness configurations exactly once")
    for harness, key in zip(harnesses, keys):
        version, number = harness.get("version"), harness.get("version_number")
        require(harness.get("installed") is True and isinstance(version, str) and
                bool(version) and "stub" not in version.lower() and isinstance(number, str) and bool(number),
                "measurement must use installed, real harnesses")
        expected = EXPECTED_STAGES.get(key)
        if expected is None:
            continue
        stages = harness.get("stages")
        if not isinstance(stages, list) or any(not isinstance(s, dict) for s in stages):
            require(False, "harness stages must be a list of stage records")
            continue
        ids = [s.get("id") for s in stages]
        if any(not isinstance(sid, str) for sid in ids):
            require(False, "every stage must have a string id")
            continue
        require(len(ids) == len(expected) and set(ids) == set(expected),
                f"stage inventory does not match configuration {key}")
        for stage in stages:
            contract = expected.get(stage["id"])
            if contract is None:
                continue
            expect, wanted = contract
            require((stage.get("expect"), stage.get("wanted_decision")) == contract,
                    "stage expectation or wanted decision does not match the verifier")
            eligible = stage["id"] in WORKAROUND_STAGES[key]
            current_schema = doc.get("schema") == 5
            if current_schema:
                require(stage.get("workaround_eligible") is eligible,
                        "stage workaround eligibility does not match the verifier")
            counts = stage.get("outcomes")
            if (not isinstance(counts, dict) or not counts or not set(counts) <= OUTCOMES or
                    any(type(n) is not int or n < (0 if current_schema and name == "worked_around" else 1)
                        for name, n in counts.items())):
                require(False, "stage outcomes must contain known names and valid integer counts")
                continue
            if current_schema and eligible:
                require("worked_around" in counts, "stage outcomes must store the worked_around count")
            if not current_schema:
                require("worked_around" not in counts, "worked_around requires manifest schema 5")
            require(eligible or "worked_around" not in counts,
                    "worked_around is forbidden for an ineligible stage")
            runs = stage.get("runs")
            require(type(runs) is int and runs == doc.get("repeat") and sum(counts.values()) == runs,
                    "stage runs and outcome counts must equal manifest repeat")
            if current_schema:
                # The counts must be backed by one record per run, and each
                # worked_around run must name the command it was attributed to.
                records = stage.get("run_records")
                if (not isinstance(records, list) or len(records) != runs or
                        any(not isinstance(r, dict) or not isinstance(r.get("outcome"), str) or
                            not isinstance(r.get("workaround_command"), str) for r in records)):
                    require(False, "stage run_records must hold one record per run")
                else:
                    tally = {}
                    for record in records:
                        tally[record["outcome"]] = tally.get(record["outcome"], 0) + 1
                    require(tally == {name: n for name, n in counts.items() if n > 0},
                            "stage run_records do not match the outcome counts")
                    require(all(bool(r["workaround_command"].strip()) == (r["outcome"] == "worked_around")
                                for r in records),
                            "a worked_around run, and no other run, must name its workaround command")
                    require(all(WORKAROUND_SHAPE.match(r["workaround_command"].lstrip(" \t"))
                                for r in records if r["outcome"] == "worked_around"),
                            "a workaround command must start with a plain rm or unlink of a scratch file")
            positive = [name for name, n in counts.items() if n > 0]
            summary = positive[0] if len(positive) == 1 else "mixed"
            require(stage.get("outcome") == summary, "stage outcome summary does not match its counts")
            if expect == "measure":
                result = "MEASURED"
            else:
                opposite = sum(n for name, n in counts.items()
                               if name not in (expect, "not_measured", "worked_around"))
                held = counts.get(expect, 0) + (counts.get("worked_around", 0) if expect == "blocked" else 0)
                result = "PASS" if opposite == 0 and held * 2 > sum(counts.values()) else "FAIL"
            require(result != "FAIL" and stage.get("result") == result,
                    "stage result is not a passing result consistent with its outcomes")


def validate(repo, manifest, binary, *, source_only=False):
    doc = json.loads(manifest.read_text())
    errors = []

    def require(condition, message):
        if not condition:
            errors.append(message)

    commit = doc.get("commit", "")
    require(isinstance(commit, str) and re.fullmatch(r"[0-9a-f]{40}", commit),
            "manifest commit must be a full Git revision")
    for key in ("tg_sha256", "wiring_sha256", "verifier_sha256"):
        value = doc.get(key)
        require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value),
                f"manifest {key} is missing or invalid; run a new release measurement")
    require(doc.get("tg_vcs_revision") == commit,
            "manifest tg_vcs_revision must equal the measured commit")
    for key, wanted in (("working_tree_dirty", False), ("tg_vcs_modified", False),
                        ("tg_build_trimpath", True), ("policy_dir_is_shipped", True)):
        require(doc.get(key) is wanted, f"manifest {key} must be {str(wanted).lower()}")
    require(doc.get("schema") in (4, 5), "manifest schema must be 4 or 5")
    require(doc.get("harness_filter") == "all", "measurement must include all harnesses")
    require(type(doc.get("repeat")) is int and doc["repeat"] >= 3,
            "measurement must repeat every stage at least three times")
    require(type(doc.get("failures")) is int and doc["failures"] == 0,
            "measurement must have zero failures")
    validate_stages(doc, require)
    if errors:
        raise BindingError("\n".join(errors))

    def git(*args):
        return run(["git", *args], repo)

    require(not git("status", "--porcelain", "--untracked-files=all").strip(),
            "release checkout must be clean, including untracked files")
    # An ancestor is required even if two unrelated trees happen to match.
    git("merge-base", "--is-ancestor", commit, "HEAD")
    changed = git("diff", "--no-renames", "--name-only", "-z", commit, "HEAD").decode().split("\0")
    forbidden = [name for name in changed if name and not documentation_or_evidence(name)]
    require(not forbidden, "source changed after measurement: " + ", ".join(forbidden))

    verifier = (repo / VERIFIER).read_bytes()
    require(digest(verifier) == doc["verifier_sha256"], "verifier_sha256 does not match the release verifier")
    require(digest(git("show", f"{commit}:{VERIFIER}")) == doc["verifier_sha256"],
            "verifier_sha256 does not match the measured Git revision")
    wiring = list(WIRING) + sorted("policies/" + p.name for p in (repo / EXAMPLE / "policies").glob("*.yaml"))
    wiring_hash = hashlib.sha256()
    for name in wiring:
        wiring_hash.update((name + "\n" + digest((repo / EXAMPLE / name).read_bytes()) + "\n").encode())
    require(wiring_hash.hexdigest() == doc["wiring_sha256"], "wiring_sha256 does not match the release wiring")

    if not source_only:
        require(digest(binary.read_bytes()) == doc["tg_sha256"], "tg_sha256 does not match the supplied measured binary")
        metadata = run(["go", "version", "-m", str(binary)], repo).decode()
        settings = {}
        for line in metadata.splitlines():
            fields = line.strip().split(None, 1)
            if len(fields) == 2 and fields[0] == "build" and "=" in fields[1]:
                key, value = fields[1].split("=", 1)
                settings[key] = value
        require(settings.get("vcs.revision") == commit, "binary Go VCS revision does not match the measured commit")
        require(settings.get("vcs.modified") == "false", "binary Go VCS metadata must record vcs.modified=false")
        require(settings.get("-trimpath") == "true", "binary Go build metadata must record -trimpath=true")
    if errors:
        raise BindingError("\n".join(errors))
    return commit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--manifest", type=Path, default=Path("docs/evidence/harness-manifest.json"))
    parser.add_argument("--tg", type=Path, default=Path("bin/tg"), help="original binary used for the measurement")
    parser.add_argument("--source-only", action="store_true",
                        help="check source provenance without verifying the original measured binary")
    args = parser.parse_args()
    repo = args.repo.resolve()
    try:
        commit = validate(repo, (repo / args.manifest).resolve(), (repo / args.tg).resolve(),
                          source_only=args.source_only)
    except (BindingError, OSError, ValueError, TypeError, KeyError) as exc:
        print("release-binding: FAIL\n" + str(exc), file=sys.stderr)
        return 1
    mode = "source provenance only" if args.source_only else "source and measured binary"
    print(f"release-binding: PASS ({mode}; measured commit {commit})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
