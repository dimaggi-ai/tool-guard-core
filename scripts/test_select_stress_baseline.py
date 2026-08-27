#!/usr/bin/env python3
"""Behavioral tests for selecting a distinct nightly stress baseline."""

from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SELECT = ROOT / "scripts" / "select-stress-baseline.sh"


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


class SelectStressBaselineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.repo = Path(self.tempdir.name)
        git(self.repo, "init", "-q")
        git(self.repo, "config", "user.name", "Stress Test")
        git(self.repo, "config", "user.email", "stress-test@example.invalid")
        self.commit("one")
        git(self.repo, "tag", "v1.0.0")
        self.commit("two")
        git(self.repo, "tag", "v1.1.0")

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def commit(self, value: str) -> str:
        (self.repo / "payload.txt").write_text(value + "\n", encoding="utf-8")
        git(self.repo, "add", "payload.txt")
        git(self.repo, "commit", "-q", "-m", value)
        return git(self.repo, "rev-parse", "HEAD")

    def select(self, ref: str = "HEAD") -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(SELECT), ref],
            cwd=self.repo,
            capture_output=True,
            text=True,
        )

    def test_candidate_ahead_uses_latest_stable_release(self) -> None:
        self.commit("three")
        result = self.select()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "v1.1.0")

    def test_candidate_at_latest_tag_uses_preceding_release(self) -> None:
        result = self.select()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "v1.0.0")

    def test_prerelease_tag_is_not_selected(self) -> None:
        self.commit("three")
        git(self.repo, "tag", "v1.2.0-rc.1")
        result = self.select()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "v1.1.0")

    def test_fails_without_distinct_stable_release(self) -> None:
        git(self.repo, "tag", "-d", "v1.0.0")
        result = self.select()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no distinct stable release tag", result.stderr)


if __name__ == "__main__":
    unittest.main()
