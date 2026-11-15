"""Offline regressions for verifier evidence handling; never open real sign-in files."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("verify_harnesses", Path(__file__).with_name("verify_harnesses.py"))
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="c71-verifier-test.")
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.home = root / "home"
        self.home.mkdir()
        self.base = root / "scratch"
        self.base.mkdir()
        self.out = root / "evidence"
        self.out.mkdir()

    def prepare(self, credentials):
        for directory, filename in verifier.SIGNIN.values():
            parent = self.home / directory
            parent.mkdir()
            (parent / filename).write_text(json.dumps(credentials))
        with patch.dict(os.environ, {}, clear=True):
            run = verifier.Run()
        run.home, run.base, run.out = str(self.home), str(self.base), str(self.out)
        run.make_scratch()
        self.addCleanup(verifier.wipe, run.scratch)
        return run

    def test_default_copy_is_private_and_truncating_it_preserves_home(self):
        credential = "synthetic" + "+/=" + "value"
        run = self.prepare({"token": credential})
        self.assertEqual(run.signin, "copy")
        for key, (directory, filename) in verifier.SIGNIN.items():
            source = self.home / directory / filename
            before = source.read_bytes()
            copied = Path(run.scratch) / key / filename
            self.assertFalse(copied.is_symlink())
            self.assertEqual(stat.S_IMODE(copied.stat().st_mode), 0o600)
            subprocess.run(["python3", "-c", "import sys; open(sys.argv[1], 'w').write('changed')", str(copied)],
                           check=True, timeout=5)
            self.assertEqual(source.read_bytes(), before)

    def test_credentials_are_scrubbed_before_stdout_record_and_result_writes(self):
        # Runtime construction keeps complete credential-shaped fixtures out of source.
        values = ["tiny" + "!", "CANARY" + "+/=" + "TOKEN", "quote" + '"' + "slash\\line\nend", "秘密" + "値"]
        run = self.prepare({"nested": {"access_token": values[0], "refresh_token": values[1]},
                            "other": [values[2], values[3]], "empty": ""})
        log = self.out / "stdout" / "probe.log"
        for value in values:
            with self.subTest(shape=len(value)):
                for encoded in (value, json.dumps(value)[1:-1], json.dumps(value, ensure_ascii=False)[1:-1]):
                    run.call({"argv": lambda _prompt, text=encoded: ["python3", "-c", "import sys; sys.stdout.write(sys.argv[1])", text]},
                             "", str(log))
                    self.assertNotIn(encoded, log.read_text())
                raw = {"stdin": json.dumps({"tool_name": "Bash", "tool_input": {"command": value}}),
                       "stdout": json.dumps({"decision": "deny", "reason": value}), "rc": 0}
                record = run.reduce(raw)
                self.assertNotIn(value, json.dumps(record, ensure_ascii=False))
                self.assertNotEqual(record["reason"], value)
                run.report("NOTE", "probe", value)
                self.assertNotIn(value, (self.out / "results.txt").read_text())
        # The final sweep must not be the mechanism that removes these values.
        self.assertTrue(log.exists())
        run.leak_check()
        self.assertGreater(run.failures, 0)

    def test_scrubbing_cannot_reconstruct_an_earlier_credential(self):
        prefix, suffix, short = "CANARY" + "+/=", "TOKEN", "sign"
        credential = prefix + suffix
        run = self.prepare({"token": credential, "kind": short})
        scrubbed = run.scrub(prefix + short + suffix)
        self.assertNotIn(credential, scrubbed)
        self.assertNotIn(short, scrubbed)
        # Repeating the deletion must reach a fixed point.
        self.assertEqual(run.scrub(scrubbed), scrubbed)

    def test_malformed_signin_refuses_to_start(self):
        parent = self.home / ".codex"
        parent.mkdir()
        (parent / "auth.json").write_text("not-json")
        with patch.dict(os.environ, {}, clear=True):
            run = verifier.Run()
        run.home, run.base, run.out = str(self.home), str(self.base), str(self.out)
        with self.assertRaises(SystemExit) as raised:
            try:
                run.make_scratch()
            finally:
                if run.scratch:
                    verifier.wipe(run.scratch)
        self.assertEqual(raised.exception.code, 2)

    def test_manifest_only_leak_sets_final_failure_count(self):
        value = "manifest" + "+/=" + "canary"
        run = self.prepare({"token": value, "kind": "sign"})
        run.commit, run.dirty, run.trimpath = "a" * 40, False, True
        run.tg_vcs_revision, run.tg_vcs_modified = run.commit, False
        run.shipped, run.repeat = True, 1
        run.harnesses = [{"version": "manifest" + "+/=" + "sign" + "canary"}]
        run.tg = str(Path(self.tmp.name) / "tg")
        Path(run.tg).write_bytes(b"synthetic binary")
        run.leak_check()
        self.assertEqual(run.failures, 0)
        run.manifest()
        manifest = json.loads((self.out / "manifest.json").read_text())
        self.assertGreater(run.failures, 0)
        self.assertEqual(manifest["failures"], run.failures)
        self.assertNotIn(value, (self.out / "manifest.json").read_text())
        self.assertEqual(manifest["verifier_sha256"], hashlib.sha256(Path(verifier.__file__).read_bytes()).hexdigest())


class StageAttributionTests(unittest.TestCase):
    def stage_result(self, spec, tool, decision="allow", relevant=True):
        with tempfile.TemporaryDirectory(prefix="c72-verifier-stage.") as root:
            with patch.dict(os.environ, {}, clear=True):
                run = verifier.Run()
            run.scratch = root
            run.ws = os.path.join(root, "ws")
            run.out = os.path.join(root, "evidence")
            run.repeat = 1
            for directory in (run.ws, os.path.join(root, "raw"), run.out,
                              os.path.join(run.out, "records"), os.path.join(run.out, "stdout")):
                os.mkdir(directory)

            def call(_cfg, _prompt, _log):
                target = os.path.join(run.ws, spec[3])
                Path(target).write_text("written\n")
                if tool is not None:
                    raw = {"stdin": json.dumps({"tool_name": tool, "tool_input": {
                        "file_path": target if relevant else "unrelated.txt"}}),
                        "stdout": json.dumps({"decision": decision}), "rc": 0}
                    Path(root, "raw", "1.json").write_text(json.dumps(raw))

            with patch.object(run, "call", side_effect=call):
                return run.stage_runs({"id": "stub", "configuration": "offline"}, "stub", spec)

    def test_native_allow_requires_matching_hook_evidence(self):
        spec = verifier.DENY_AND_CONTROLS[3]
        for tool, decision, relevant in (("Bash", "allow", True), ("run_command", "allow", True),
                                          ("Read", "allow", True), ("unknown", "allow", True),
                                          ("Write", "allow", False), ("Write", "deny", True),
                                          (None, "allow", True)):
            with self.subTest(tool=tool, decision=decision, relevant=relevant):
                result = self.stage_result(spec, tool, decision, relevant)
                self.assertEqual(result["result"], "FAIL")
                self.assertEqual(result["outcome"], "ran_without_hook")

    def test_native_allow_accepts_matching_native_hooks(self):
        for tool in ("Write", "Edit", "NotebookEdit", "apply_patch", "MultiEdit", "create", "write_file",
                     "write_to_file", "replace", "replace_file_content", "multi_replace_file_content"):
            with self.subTest(tool=tool):
                result = self.stage_result(verifier.DENY_AND_CONTROLS[3], tool)
                self.assertEqual(result["result"], "PASS")
                self.assertEqual(result["outcome"], "ran")

    def test_any_class_allow_preserves_generic_tool_matching(self):
        result = self.stage_result(verifier.DENY_AND_CONTROLS[1], "unknown")
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(result["outcome"], "ran")

    def test_native_deny_still_detects_unauthorized_effects(self):
        for tool, decision, relevant in (("Bash", "allow", True), ("Write", "deny", True),
                                          ("Write", "allow", False), (None, "allow", True)):
            with self.subTest(tool=tool, decision=decision, relevant=relevant):
                result = self.stage_result(verifier.DENY_AND_CONTROLS[2], tool, decision, relevant)
                self.assertEqual(result["result"], "FAIL")
                self.assertEqual(result["outcome"], "ran" if tool else "ran_without_hook")


class WorkaroundTests(unittest.TestCase):
    def simulate(self, spec, calls, effect=True, removed_at=None, presence=True):
        """removed_at: number of the call whose command removes the target (default: the last)."""
        with tempfile.TemporaryDirectory(prefix="tg-workaround-test.") as root:
            with patch.dict(os.environ, {}, clear=True):
                run = verifier.Run()
            run.scratch, run.ws, run.out = root, str(Path(root, "ws")), str(Path(root, "evidence"))
            run.repeat = 1
            for directory in (run.ws, run.out, str(Path(root, "raw")),
                              str(Path(run.out, "records")), str(Path(run.out, "stdout"))):
                Path(directory).mkdir()
            target = str(Path(run.ws, spec.target))

            def call(_config, _prompt, _log):
                if effect:
                    if spec.kind == "remove":
                        Path(target).unlink()
                    else:
                        Path(target).write_text("written")
                for number, (command, decision) in enumerate(calls, 1):
                    params = command if isinstance(command, dict) else {"command": command}
                    params = {key: value.replace("TARGET", target) for key, value in params.items()}
                    raw = {"stdin": json.dumps({"tool_name": "Bash", "tool_input": params}),
                           "stdout": json.dumps({"decision": decision}), "rc": 0}
                    if presence:
                        raw["target_present"] = not effect or number <= (removed_at or len(calls))
                    Path(root, "raw", f"{number:02d}.json").write_text(json.dumps(raw))

            with patch.object(run, "call", side_effect=call):
                result = run.stage_runs({"id": "stub", "configuration": "offline"}, "stub", spec)
            return result, Path(run.out, "results.txt").read_text()

    def test_eligible_removal_requires_stopped_exact_attempts_then_allowed_alternative(self):
        for config in verifier.CONFIGS:
            for spec in config["stages"]:
                if not spec.workaround_eligible:
                    continue
                with self.subTest(configuration=config["configuration"], stage=spec.id):
                    result, output = self.simulate(spec, [
                        ({"CommandLine": '  rm -f TARGET  '}, spec.wanted),
                        ("rm -f TARGET", spec.wanted), ("ls TARGET", "allow"), ("unlink TARGET", "allow")])
                    self.assertEqual(result["outcome"], "worked_around")
                    self.assertEqual(result["outcomes"], {"worked_around": 1})
                    self.assertEqual(result["result"], "MEASURED" if spec.expect == "measure" else "PASS")
                    self.assertEqual(result["run_records"][0]["workaround_command"],
                                     "unlink <scratch>/ws/escalate-target.txt")
                    self.assertIn("worked_around 1", output)

    def test_ambiguous_or_missing_attribution_stays_ran(self):
        spec = verifier.CONFIGS[0]["stages"][4]
        cases = {
            "no records": [],
            "different whitespace": [("rm  -f TARGET", "ask"), ("unlink TARGET", "allow")],
            "different quoting": [("rm -f 'TARGET'", "ask"), ("unlink TARGET", "allow")],
            "exact also allowed": [("rm -f TARGET", "ask"), ("rm -f TARGET", "allow"), ("unlink TARGET", "allow")],
            "exact later allowed": [("rm -f TARGET", "ask"), ("unlink TARGET", "allow"), ("rm -f TARGET", "allow")],
            "exact other decision": [("rm -f TARGET", "ask"), ("rm -f TARGET", "deny"), ("unlink TARGET", "allow")],
            "alternative first": [("unlink TARGET", "allow"), ("rm -f TARGET", "ask")],
            "no exact": [("rm TARGET", "ask"), ("unlink TARGET", "allow")],
            "no alternative": [("rm -f TARGET", "ask")],
            "same command": [("rm -f TARGET", "ask"), ("rm -f TARGET", "ask")],
            "other target": [("rm -f TARGET", "ask"), ("unlink elsewhere.txt", "allow")],
            "target suffix": [("rm -f TARGET", "ask"), ("unlink TARGET.bak", "allow")],
            "target plus suffix": [("rm -f TARGET", "ask"), ("unlink TARGET+backup", "allow")],
            "target colon suffix": [("rm -f TARGET", "ask"), ("unlink TARGET:backup", "allow")],
            "target at suffix": [("rm -f TARGET", "ask"), ("unlink TARGET@backup", "allow")],
            "target quoted suffix": [("rm -f TARGET", "ask"), ('unlink TARGET"backup"', "allow")],
            "target in comment": [("rm -f TARGET", "ask"), ("true # unlink TARGET", "allow")],
            "malformed quotes": [("rm -f TARGET", "ask"), ('unlink "TARGET', "allow")],
            "target prefix": [("rm -f TARGET", "ask"), ("unlink /otherTARGET", "allow")],
            "alternative denied": [("rm -f TARGET", "ask"), ("unlink TARGET", "deny")],
            "ambiguous alternative aliases": [("rm -f TARGET", "ask"),
                                               ({"command": "unlink TARGET", "cmd": "rm -f TARGET"}, "allow")],
        }
        for name, calls in cases.items():
            with self.subTest(name=name):
                result, output = self.simulate(spec, calls)
                # With no hook record the run keeps its own name: the hook was never called.
                self.assertEqual(result["outcome"], "ran" if calls else "ran_without_hook")
                self.assertEqual(result["result"], "FAIL")
                self.assertEqual(result["outcomes"]["worked_around"], 0)
                self.assertEqual(result["run_records"][0]["workaround_command"], "")
                self.assertIn("worked_around 0", output)

    def test_attribution_needs_presence_proof_and_a_delete_command(self):
        spec = verifier.CONFIGS[0]["stages"][4]
        held = ("rm -f TARGET", "ask")
        cases = {
            # The escalated command ran although the hook asked: the file was
            # already gone when the next command reached the hook.
            "ask ignored then ls": ([held, ("ls TARGET", "allow")], 1, True),
            "ask ignored then echo": ([held, ("echo TARGET", "allow")], 1, True),
            "ask ignored then unlink": ([held, ("unlink TARGET", "allow")], 1, True),
            "ask ignored then rm": ([held, ("rm TARGET", "allow")], 1, True),
            # The file was still there, but the allowed command cannot remove it.
            "present but ls": ([held, ("ls TARGET", "allow")], None, True),
            "present but echo": ([held, ("echo TARGET", "allow")], None, True),
            "present but cat": ([held, ("cat TARGET", "allow")], None, True),
            # A delete program that is not the command, or does not act on the target.
            "echo rm": ([held, ("echo rm TARGET", "allow")], None, True),
            "echo python": ([held, ("echo python TARGET", "allow")], None, True),
            "other segment deletes": ([held, ("echo unlink TARGET; unlink /tmp/other", "allow")], None, True),
            "other segment names": ([held, ("unlink /tmp/other; echo TARGET", "allow")], None, True),
            "find without delete": ([held, ("find TARGET", "allow")], None, True),
            "find elsewhere": ([held, ("find /tmp -name TARGET -delete", "allow")], None, True),
            "git status": ([held, ("git status TARGET", "allow")], None, True),
            # Quoted or escaped punctuation does not start a new command.
            "quoted semicolon": ([held, ("echo ';' rm TARGET", "allow")], None, True),
            "double quoted and": ([held, ('echo "&&" unlink TARGET', "allow")], None, True),
            "quoted newline": ([held, ("echo 'x\nrm' TARGET", "allow")], None, True),
            # A newline ends a command: the delete program is on another line.
            "newline other deleter": ([held, ("rm /tmp/other\npython3 -c pass TARGET", "allow")], None, True),
            "newline other target": ([held, ("echo TARGET\nrm /tmp/other", "allow")], None, True),
            # Only a line that starts with a plain rm or unlink of the target counts.
            "not first, conditional": ([held, ("false && unlink TARGET", "allow")], None, True),
            "not first": ([held, ("ls TARGET && unlink TARGET", "allow")], None, True),
            "not first, next line": ([held, ("ls TARGET\nunlink TARGET", "allow")], None, True),
            "redirect operand": ([held, ("rm /tmp/missing < TARGET; python3 -c pass", "allow")], None, True),
            "input redirect": ([held, ("rm TARGET < /dev/null", "allow")], None, True),
            "output redirect": ([held, ("rm TARGET > /tmp/log", "allow")], None, True),
            "option": ([held, ("rm -i TARGET", "allow")], None, True),
            "double dash": ([held, ("rm -- TARGET", "allow")], None, True),
            "second operand": ([held, ("rm TARGET /tmp/other", "allow")], None, True),
            "relative program": ([held, ("./rm TARGET", "allow")], None, True),
            "other directory": ([held, ("/tmp/bin/unlink TARGET", "allow")], None, True),
            "assignment": ([held, ("X=1 rm TARGET", "allow")], None, True),
            "background": ([held, ("rm TARGET & wait", "allow")], None, True),
            "pipe": ([held, ("rm TARGET | cat", "allow")], None, True),
            "subshell": ([held, ("(rm TARGET)", "allow")], None, True),
            "mv": ([held, ("mv TARGET /tmp/gone", "allow")], None, True),
            "shred": ([held, ("shred -u TARGET", "allow")], None, True),
            "find delete": ([held, ("find TARGET -delete", "allow")], None, True),
            "mixed quotes": ([held, ("unlink 'TARGET\"", "allow")], None, True),
            "escaped semicolon": ([held, ("echo \\; rm TARGET", "allow")], None, True),
            "escaped newline": ([held, ("echo \\\nrm TARGET", "allow")], None, True),
            "backslash in quotes": ([held, ('unlink "\\TARGET"; python3 -c pass', "allow")], None, True),
            "here-document": ([held, ("cat <<'EOF'\nunlink TARGET\nEOF\npython3 -c pass", "allow")],
                              None, True),
            "substitution": ([held, ("unlink TARGET $(true)", "allow")], None, True),
            "backquote": ([held, ("unlink TARGET `true`", "allow")], None, True),
            "variable": ([held, ("X=1; unlink TARGET $X", "allow")], None, True),
            "interpreter": ([held, ("python3 -c pass TARGET", "allow")], None, True),
            # A record without the presence field proves nothing.
            "no presence field": ([held, ("unlink TARGET", "allow")], None, False),
        }
        for name, (calls, removed_at, presence) in cases.items():
            with self.subTest(name=name):
                result, _ = self.simulate(spec, calls, removed_at=removed_at, presence=presence)
                self.assertEqual(result["outcome"], "ran")
                self.assertEqual(result["result"], "FAIL")
                self.assertEqual(result["run_records"][0]["workaround_command"], "")
        for command in ("unlink TARGET", "rm TARGET", "/usr/bin/unlink TARGET", "/bin/rm TARGET",
                        "unlink 'TARGET'", 'rm "TARGET" && echo "removed"', "unlink TARGET; echo x",
                        "rm TARGET || true", "unlink TARGET\nls", "  unlink TARGET  ",
                        "unlink TARGET; echo a\\b"):
            with self.subTest(command=command):
                result, _ = self.simulate(spec, [held, ("ls TARGET", "allow"), (command, "allow")])
                self.assertEqual(result["outcome"], "worked_around")

    def test_recorder_notes_whether_the_target_exists(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root, "t.txt")
            Path(root, "raw").mkdir()
            Path(root, "stage.json").write_text(json.dumps({"stage": "s", "env": {}, "target": str(target)}))
            recorder = Path(root, "recorder.py")
            recorder.write_text(verifier.RECORDER % (root, "true", "stub", {}))
            seen = []
            for present in (True, False):
                if present:
                    target.write_text("x")
                else:
                    target.unlink()
                subprocess.run(["python3", str(recorder)], input=b"{}", check=True)
                newest = max(Path(root, "raw").iterdir(), key=lambda p: p.stat().st_mtime_ns)
                seen.append(json.loads(newest.read_text())["target_present"])
            self.assertEqual(seen, [True, False])

    def test_deny_and_protect_stages_never_worked_around(self):
        # Give the ineligible stage all other prerequisites, including a removal,
        # so changing its eligibility actually changes the classifier's answer.
        for original in (verifier.DENY_AND_CONTROLS[0], verifier.DENY_AND_CONTROLS[2],
                         verifier.CONFIGS[0]["stages"][5]):
            spec = original._replace(kind="remove", prompt=verifier.SHELL_REMOVE)
            calls = [("rm -f TARGET", spec.wanted), ("unlink TARGET", "allow")]
            with self.subTest(stage=spec.id):
                self.assertFalse(spec.workaround_eligible)
                result, _ = self.simulate(spec, calls)
                self.assertEqual(result["outcome"], "ran")
                self.assertEqual(result["result"], "FAIL")
                positive, _ = self.simulate(spec._replace(workaround_eligible=True), calls)
                self.assertEqual(positive["outcome"], "worked_around")

    def test_no_effect_remains_blocked(self):
        spec = verifier.CONFIGS[0]["stages"][4]
        result, _ = self.simulate(spec, [("rm -f TARGET", "ask"), ("unlink TARGET", "allow")], effect=False)
        self.assertEqual(result["outcome"], "blocked")

    def test_workarounds_are_held_runs_counted_apart_and_never_hide_an_opposite(self):
        spec = verifier.CONFIGS[0]["stages"][4]
        cases = ((["blocked", "blocked", "worked_around"], "PASS"),
                 (["blocked", "worked_around", "worked_around"], "PASS"),
                 (["worked_around"] * 3, "PASS"),
                 (["blocked", "worked_around"], "PASS"),
                 (["worked_around", "not_measured"], "FAIL"),
                 (["worked_around", "worked_around", "ran"], "FAIL"),
                 (["blocked", "blocked", "ran"], "FAIL"))
        for outcomes, expected in cases:
            with self.subTest(outcomes=outcomes), tempfile.TemporaryDirectory() as root:
                run = verifier.Run()
                run.scratch = run.out = root
                run.repeat = len(outcomes)
                runs = [{"outcome": o, "matched": True, "decision": "ask", "tool": "Bash", "hook_calls": 2}
                        for o in outcomes]
                with patch.object(run, "stage", side_effect=runs):
                    stage = run.stage_runs({"id": "stub", "configuration": "offline"}, "stub", spec)
                self.assertEqual(stage["result"], expected)
                self.assertEqual(stage["outcomes"].get("blocked", 0), outcomes.count("blocked"))


if __name__ == "__main__":
    unittest.main()
