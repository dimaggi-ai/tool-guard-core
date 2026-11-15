"""Exercise release binding with real Git histories and Go build metadata."""

import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


spec = importlib.util.spec_from_file_location("binding", Path(__file__).with_name("check-harness-evidence.py"))
binding = importlib.util.module_from_spec(spec)
spec.loader.exec_module(binding)
verifier_spec = importlib.util.spec_from_file_location(
    "verifier", Path(__file__).resolve().parents[1] / binding.VERIFIER)
verifier = importlib.util.module_from_spec(verifier_spec)
verifier_spec.loader.exec_module(verifier)


def measured_harnesses():
    # The producer supplies the fixture inventory, independently of the checker.
    entries = []
    for config in verifier.CONFIGS:
        stages = []
        for sid, expect, _kind, _target, wanted, _cls, _prompt, _env, _eligible in config["stages"]:
            outcome = expect if expect != "measure" else "not_measured"
            stages.append({"id": sid, "expect": expect, "wanted_decision": wanted,
                           "runs": 3, "outcomes": {outcome: 3}, "outcome": outcome,
                           "result": "MEASURED" if expect == "measure" else "PASS"})
        entries.append({"id": config["id"], "configuration": config["configuration"],
                        "installed": True, "version_number": "1.0.0", "version": "1.0.0",
                        "stages": stages})
    return entries


def command(repo, *args):
    env = dict(os.environ)
    for role in ("AUTHOR", "COMMITTER"):
        env[f"GIT_{role}_NAME"] = "DIMAGGI AI"
        env[f"GIT_{role}_EMAIL"] = "266338701+dimaggi-ai@users.noreply.github.com"
    result = subprocess.run(args, cwd=repo, env=env, capture_output=True, text=True, timeout=90)
    if result.returncode:
        raise AssertionError(f"{args}: {result.stdout}\n{result.stderr}")
    return result.stdout.strip()


def commit(repo):
    command(repo, "git", "add", "-A")
    command(repo, "git", "-c", "user.name=DIMAGGI AI", "-c",
            "user.email=266338701+dimaggi-ai@users.noreply.github.com",
            "-c", "commit.gpgsign=false", "commit", "-qm",
            "fixture\n\nCo-Authored-By: Codex <noreply@openai.com>")
    return command(repo, "git", "rev-parse", "HEAD")


class WorkaroundBindingTests(unittest.TestCase):
    def fixture(self):
        harnesses = measured_harnesses()
        for harness, config in zip(harnesses, verifier.CONFIGS):
            for stage, spec in zip(harness["stages"], config["stages"]):
                stage["workaround_eligible"] = spec.workaround_eligible
                if spec.workaround_eligible:
                    stage["outcomes"]["worked_around"] = 0
        doc = {"schema": 5, "repeat": 3, "harnesses": harnesses}
        for harness in harnesses:
            for stage in harness["stages"]:
                self.records(stage)
        return doc

    @staticmethod
    def records(stage):
        """Write the per-run records that back the stage counts."""
        stage["run_records"] = [
            {"outcome": name, "workaround_command": "unlink <scratch>/ws/t" if name == "worked_around" else ""}
            for name, n in stage["outcomes"].items() for _ in range(n)]

    def errors(self, doc):
        errors = []
        binding.validate_stages(doc, lambda condition, message: None if condition else errors.append(message))
        return errors

    def test_eligible_majority_with_workaround_passes(self):
        doc = self.fixture()
        stage = doc["harnesses"][0]["stages"][4]
        stage.update(outcomes={"blocked": 2, "worked_around": 1}, outcome="mixed")
        self.records(stage)
        self.assertEqual(self.errors(doc), [])

    def test_counts_need_matching_run_records(self):
        def stage_of(doc):
            stage = doc["harnesses"][0]["stages"][4]
            stage.update(outcomes={"blocked": 0, "worked_around": 3}, outcome="worked_around")
            del stage["outcomes"]["blocked"]
            self.records(stage)
            return stage
        doc = self.fixture()
        stage_of(doc)
        self.assertEqual(self.errors(doc), [])
        changes = {
            "missing": lambda s: s.pop("run_records"),
            "empty": lambda s: s.update(run_records=[]),
            "short": lambda s: s["run_records"].pop(),
            "not records": lambda s: s.update(run_records=["worked_around"] * 3),
            "other outcomes": lambda s: s["run_records"][0].update(outcome="ran"),
            "no command": lambda s: s["run_records"][0].update(workaround_command=" "),
            "unrelated command": lambda s: s["run_records"][0].update(workaround_command="touch unrelated"),
            "not first": lambda s: s["run_records"][0].update(
                workaround_command="ls && unlink <scratch>/ws/t"),
            "option": lambda s: s["run_records"][0].update(workaround_command="rm -i <scratch>/ws/t"),
            "outside scratch": lambda s: s["run_records"][0].update(workaround_command="unlink /etc/hosts"),
            "command missing": lambda s: s["run_records"][0].pop("workaround_command"),
        }
        for name, change in changes.items():
            with self.subTest(name=name):
                doc = self.fixture()
                change(stage_of(doc))
                self.assertNotEqual(self.errors(doc), [])
        doc = self.fixture()
        doc["harnesses"][0]["stages"][0]["run_records"][0]["workaround_command"] = "unlink x"
        self.assertIn("a worked_around run, and no other run, must name its workaround command", self.errors(doc))

    def test_workarounds_count_as_held_runs(self):
        for counts in ({"blocked": 1, "worked_around": 2}, {"worked_around": 3}):
            with self.subTest(counts=counts):
                doc = self.fixture()
                stage = doc["harnesses"][0]["stages"][4]
                stage.update(outcomes=counts, outcome="mixed" if len(counts) > 1 else "worked_around")
                self.records(stage)
                self.assertEqual(self.errors(doc), [])

    def test_workarounds_cannot_hide_opposite_or_missing_majority(self):
        for counts in ({"blocked": 1, "ran": 1, "worked_around": 1}, {"ran": 1, "worked_around": 2},
                       {"not_measured": 2, "worked_around": 1}):
            with self.subTest(counts=counts):
                doc = self.fixture()
                stage = doc["harnesses"][0]["stages"][4]
                stage.update(outcomes=counts, outcome="mixed" if len(counts) > 1 else "worked_around")
                self.records(stage)
                self.assertIn("stage result is not a passing result consistent with its outcomes", self.errors(doc))

    def test_ineligible_stages_reject_key_even_when_zero_or_claimed_eligible(self):
        for config_index, config in enumerate(verifier.CONFIGS):
            for stage_index, spec in enumerate(config["stages"]):
                if spec.workaround_eligible:
                    continue
                for count in (0, 1):
                    with self.subTest(config=config_index, stage=spec.id, count=count):
                        doc = self.fixture()
                        stage = doc["harnesses"][config_index]["stages"][stage_index]
                        stage["outcomes"]["worked_around"] = count
                        stage["workaround_eligible"] = True
                        errors = self.errors(doc)
                        self.assertIn("worked_around is forbidden for an ineligible stage", errors)
                        self.assertIn("stage workaround eligibility does not match the verifier", errors)

    def test_eligible_zero_count_is_required_and_does_not_change_summary(self):
        doc = self.fixture()
        self.assertEqual(self.errors(doc), [])
        del doc["harnesses"][0]["stages"][4]["outcomes"]["worked_around"]
        self.assertIn("stage outcomes must store the worked_around count", self.errors(doc))

    def test_legacy_counts_remain_valid_but_cannot_claim_workarounds(self):
        doc = {"schema": 4, "repeat": 3, "harnesses": measured_harnesses()}
        self.assertEqual(self.errors(doc), [])
        stage = doc["harnesses"][0]["stages"][4]
        stage.update(outcomes={"blocked": 2, "worked_around": 1}, outcome="mixed")
        self.records(stage)
        self.assertIn("worked_around requires manifest schema 5", self.errors(doc))


class ReleaseBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = tempfile.TemporaryDirectory(prefix="tg-binding-base-")
        cls.addClassCleanup(cls.base.cleanup)
        root = Path(cls.base.name)
        cls.repo = root / "repo"
        cls.repo.mkdir()
        command(cls.repo, "git", "init", "-q", "-b", "fix/leak-guards-portability")
        # Text-mode writes produce CRLF on Windows, and a runner-wide
        # core.autocrlf would store LF blobs. Keep blobs equal to the bytes on
        # disk so the checker compares the same content (the real repository
        # forces LF through .gitattributes).
        command(cls.repo, "git", "config", "core.autocrlf", "false")
        (cls.repo / "go.mod").write_text("module binding.fixture\n\ngo 1.20\n")
        (cls.repo / "main.go").write_text('package main\nfunc main() {}\n')
        for name in (*binding.WIRING, "policies/example.yaml", "verify_harnesses.py"):
            path = cls.repo / binding.EXAMPLE / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture\n")
        measured = commit(cls.repo)
        cls.binary = root / "tg"
        command(cls.repo, "go", "build", "-trimpath", "-o", str(cls.binary), ".")
        wiring = binding.hashlib.sha256()
        for name in (*binding.WIRING, "policies/example.yaml"):
            wiring.update((name + "\n" + binding.digest((cls.repo / binding.EXAMPLE / name).read_bytes()) + "\n").encode())
        cls.doc = {
            "schema": 4, "commit": measured, "working_tree_dirty": False,
            "tg_vcs_revision": measured, "tg_vcs_modified": False, "tg_build_trimpath": True,
            "tg_sha256": binding.digest(cls.binary.read_bytes()),
            "verifier_sha256": binding.digest((cls.repo / binding.VERIFIER).read_bytes()),
            "wiring_sha256": wiring.hexdigest(), "policy_dir_is_shipped": True,
            "harness_filter": "all", "repeat": 3, "failures": 0,
            "harnesses": measured_harnesses(),
        }
        manifest = cls.repo / "docs/evidence/harness-manifest.json"
        manifest.parent.mkdir(parents=True)
        manifest.write_text(json.dumps(cls.doc))
        commit(cls.repo)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tg-binding-test-")
        self.addCleanup(self.temp.cleanup)
        self.checkout = Path(self.temp.name) / "repo"
        shutil.copytree(self.repo, self.checkout)
        self.manifest = self.checkout / "docs/evidence/harness-manifest.json"

    def check(self, message=None, binary=None):
        if message:
            with self.assertRaisesRegex(binding.BindingError, message):
                binding.validate(self.checkout, self.manifest, binary or self.binary)
        else:
            self.assertEqual(binding.validate(self.checkout, self.manifest, binary or self.binary), self.doc["commit"])

    def update_manifest(self, **values):
        doc = json.loads(self.manifest.read_text())
        doc.update(values)
        self.manifest.write_text(json.dumps(doc))
        commit(self.checkout)

    def test_source_only_does_not_require_measured_binary(self):
        self.assertEqual(binding.validate(self.checkout, self.manifest, None, source_only=True),
                         self.doc["commit"])

    def test_source_only_still_rejects_source_changes(self):
        (self.checkout / "main.go").write_text("changed\n")
        commit(self.checkout)
        with self.assertRaisesRegex(binding.BindingError, "source changed after measurement"):
            binding.validate(self.checkout, self.manifest, None, source_only=True)

    def test_source_only_still_checks_provenance(self):
        self.update_manifest(tg_vcs_modified=True)
        with self.assertRaisesRegex(binding.BindingError, "tg_vcs_modified must be false"):
            binding.validate(self.checkout, self.manifest, None, source_only=True)

    def test_documentation_and_evidence_only_commit_passes(self):
        (self.checkout / "README.md").write_text("Release notes\n")
        commit(self.checkout)
        self.check()

    def test_truncated_and_duplicate_configurations_are_rejected(self):
        for mutation in (lambda h: h[:3], lambda h: h + [h[0]],
                         lambda h: [h[0], h[0], *h[2:]]):
            with self.subTest(mutation=mutation):
                self.update_manifest(harnesses=mutation(measured_harnesses()))
                self.check("five harness configurations exactly once")

    def test_missing_duplicate_and_unknown_stages_are_rejected(self):
        for ids in (("shell_deny",), ("shell_deny",) * 6, ("unknown",) * 6):
            with self.subTest(ids=ids):
                harnesses = measured_harnesses()
                template = harnesses[0]["stages"][0]
                harnesses[0]["stages"] = [{**template, "id": sid} for sid in ids]
                self.update_manifest(harnesses=harnesses)
                self.check("stage inventory does not match")

    def test_malformed_stage_counts_results_and_expectations_are_rejected(self):
        cases = [
            ({"outcomes": {"unknown": 3}}, "known names and valid integer"),
            ({"outcomes": {"blocked": 4, "ran": -1}}, "known names and valid integer"),
            ({"outcomes": {"blocked": True, "not_measured": 2}}, "known names and valid integer"),
            ({"outcomes": {"blocked": 3.0}}, "known names and valid integer"),
            ({"outcomes": {"blocked": 3, "ran": 0}}, "known names and valid integer"),
            ({"outcomes": {"blocked": 2}}, "counts must equal"),
            ({"runs": 4}, "counts must equal"),
            ({"result": "UNKNOWN"}, "stage result"),
            ({"result": "MEASURED"}, "stage result"),
            ({"result": "FAIL"}, "stage result"),
            ({"outcomes": {"ran": 3}, "outcome": "ran"}, "stage result"),
            ({"outcomes": {"blocked": 1, "not_measured": 2}, "outcome": "mixed"}, "stage result"),
            ({"outcomes": {"blocked": 2, "ran": 1}, "outcome": "mixed"}, "stage result"),
            ({"outcome": "mixed"}, "outcome summary"),
            ({"expect": "measure"}, "expectation or wanted decision"),
            ({"wanted_decision": "allow"}, "expectation or wanted decision"),
        ]
        for changes, message in cases:
            with self.subTest(changes=changes):
                harnesses = measured_harnesses()
                harnesses[0]["stages"][0].update(changes)
                self.update_manifest(harnesses=harnesses)
                self.check(message)

    def test_measurement_stage_cannot_claim_pass(self):
        harnesses = measured_harnesses()
        harnesses[1]["stages"][0]["result"] = "PASS"
        self.update_manifest(harnesses=harnesses)
        self.check("stage result")

    def test_majority_with_unmeasured_runs_passes(self):
        harnesses = measured_harnesses()
        harnesses[0]["stages"][0].update(outcomes={"blocked": 2, "not_measured": 1}, outcome="mixed")
        self.update_manifest(harnesses=harnesses)
        self.check()

    def test_engine_verifier_hook_and_policy_changes_require_remeasurement(self):
        baseline = command(self.checkout, "git", "rev-parse", "HEAD")
        for name in ("main.go", binding.VERIFIER, binding.EXAMPLE + "/hooks/guard-hook.sh",
                     binding.EXAMPLE + "/policies/example.yaml", "docs/executable.py"):
            with self.subTest(path=name):
                command(self.checkout, "git", "reset", "--hard", baseline)
                path = self.checkout / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("changed\n")
                commit(self.checkout)
                self.check("source changed after measurement: " + re.escape(name))

    def test_modified_worktree_is_rejected(self):
        (self.checkout / "main.go").write_text("dirty\n")
        self.check("release checkout must be clean")

    def test_untracked_source_is_rejected(self):
        (self.checkout / "extra.go").write_text("package main\n")
        self.check("release checkout must be clean")

    def test_unrelated_history_is_rejected(self):
        command(self.checkout, "git", "checkout", "--orphan", "unrelated")
        commit(self.checkout)
        self.check("merge-base --is-ancestor")

    def test_missing_legacy_provenance_is_rejected(self):
        doc = json.loads(self.manifest.read_text())
        for key in ("tg_vcs_revision", "tg_vcs_modified", "verifier_sha256"):
            del doc[key]
        self.manifest.write_text(json.dumps(doc))
        commit(self.checkout)
        self.check("verifier_sha256 is missing")

    def test_manifest_binary_digest_is_checked(self):
        self.update_manifest(tg_sha256="0" * 64)
        self.check("tg_sha256 does not match")

    def test_manifest_verifier_digest_is_checked(self):
        self.update_manifest(verifier_sha256="0" * 64)
        self.check("verifier_sha256 does not match")

    def test_manifest_wiring_digest_is_checked(self):
        self.update_manifest(wiring_sha256="0" * 64)
        self.check("wiring_sha256 does not match")

    def test_manifest_dirty_binary_is_rejected(self):
        self.update_manifest(tg_vcs_modified=True)
        self.check("tg_vcs_modified must be false")

    def test_manifest_revision_mismatch_is_rejected(self):
        self.update_manifest(tg_vcs_revision="0" * 40)
        self.check("tg_vcs_revision must equal")

    def test_actual_binary_revision_is_checked(self):
        # Advancing both manifest revisions cannot relabel an older binary.
        current = command(self.checkout, "git", "rev-parse", "HEAD")
        self.update_manifest(commit=current, tg_vcs_revision=current)
        self.check("binary Go VCS revision does not match")

    def test_actual_dirty_binary_is_checked_even_with_matching_digest(self):
        (self.checkout / "main.go").write_text("package main\nfunc main() { println(1) }\n")
        binary = Path(self.temp.name) / "dirty-tg"
        command(self.checkout, "go", "build", "-trimpath", "-o", str(binary), ".")
        command(self.checkout, "git", "checkout", "--", "main.go")
        self.update_manifest(tg_sha256=binding.digest(binary.read_bytes()))
        self.check("binary Go VCS metadata must record vcs.modified=false", binary)

    def test_binary_without_vcs_is_rejected_even_with_matching_digest(self):
        binary = Path(self.temp.name) / "no-vcs-tg"
        command(self.checkout, "go", "build", "-trimpath", "-buildvcs=false", "-o", str(binary), ".")
        self.update_manifest(tg_sha256=binding.digest(binary.read_bytes()))
        self.check("binary Go VCS revision does not match", binary)

    def test_actual_trimpath_is_checked_even_with_matching_digest(self):
        binary = Path(self.temp.name) / "no-trimpath-tg"
        command(self.checkout, "go", "build", "-o", str(binary), ".")
        self.update_manifest(tg_sha256=binding.digest(binary.read_bytes()))
        self.check("binary Go build metadata must record -trimpath=true", binary)


if __name__ == "__main__":
    unittest.main()
