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


if __name__ == "__main__":
    unittest.main()
