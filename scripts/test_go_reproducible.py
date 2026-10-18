"""Checks for the artifact comparison and publication gate."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReproducibilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.dist = self.root / "dist"
        self.dist.mkdir()
        self.binary = self.dist / "tg_linux_amd64_v1" / "tg"
        self.binary.parent.mkdir()
        self.binary.write_bytes(b"binary")
        self.archive = self.dist / "release.tar.gz"
        self.archive.write_bytes(b"archive")
        self.artifacts = [
            {"type": "Binary", "path": "dist/tg_linux_amd64_v1/tg"},
            {"type": "Archive", "path": "dist/release.tar.gz"},
        ]
        self.write_artifacts()
        self.manifest = load("go-reproducible-manifest")
        self.gate = load("verify-go-release-archive")

    def write_artifacts(self):
        (self.dist / "artifacts.json").write_text(json.dumps(self.artifacts))

    def evidence(self):
        path = self.root / "build1.sha256"
        path.write_text(self.manifest.manifest(self.dist))
        return path

    def test_manifest_ignores_input_order(self):
        first = self.manifest.manifest(self.dist)
        self.artifacts.reverse()
        self.write_artifacts()
        self.assertEqual(first, self.manifest.manifest(self.dist))
        self.assertEqual(len(first.splitlines()), 2)

    def test_binary_and_archive_changes_change_manifest(self):
        first = self.manifest.manifest(self.dist)
        self.binary.write_bytes(b"changed binary")
        second = self.manifest.manifest(self.dist)
        self.assertNotEqual(first, second)
        self.archive.write_bytes(b"changed archive")
        self.assertNotEqual(second, self.manifest.manifest(self.dist))

    def test_missing_artifact_fails(self):
        self.binary.unlink()
        with self.assertRaises(FileNotFoundError):
            self.manifest.manifest(self.dist)

    def test_empty_artifacts_fail(self):
        self.artifacts.clear()
        self.write_artifacts()
        with self.assertRaises(ValueError):
            self.manifest.manifest(self.dist)

    def test_duplicate_artifacts_fail(self):
        self.artifacts.append(self.artifacts[0])
        self.write_artifacts()
        with self.assertRaises(ValueError):
            self.manifest.manifest(self.dist)

    def test_matching_archive_passes(self):
        self.gate.verify(self.evidence(), self.archive)

    def test_mismatch_fails_before_sbom(self):
        evidence = self.evidence()
        self.archive.write_bytes(b"different")
        with self.assertRaisesRegex(ValueError, "does not match"):
            self.gate.verify(evidence, self.archive)

    def test_unknown_archive_fails(self):
        evidence = self.evidence()
        evidence.write_text("")
        with self.assertRaisesRegex(ValueError, "does not match"):
            self.gate.verify(evidence, self.archive)

    def test_missing_manifest_fails(self):
        with self.assertRaises(FileNotFoundError):
            self.gate.verify(self.root / "missing", self.archive)

    def test_sbom_command_preserved_and_blocked_on_mismatch(self):
        evidence = self.evidence()
        tool = self.root / "syft"
        tool.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$HOME/args"\n')
        tool.chmod(0o755)
        env = dict(os.environ, PATH=f"{self.root}:{os.environ['PATH']}", HOME=str(self.root))
        cmd = ["python3", str(ROOT / "scripts/verify-go-release-archive.py"),
               str(evidence), str(self.archive), "sbom.json"]
        subprocess.run(cmd, check=True, env=env, capture_output=True)
        args = self.root / "args"
        self.assertEqual(args.read_text().splitlines(),
                         [str(self.archive), "--output", "spdx-json=sbom.json", "--enrich", "all"])
        args.unlink()
        self.archive.write_bytes(b"tampered")
        result = subprocess.run(cmd, env=env, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(args.exists())


if __name__ == "__main__":
    unittest.main()
