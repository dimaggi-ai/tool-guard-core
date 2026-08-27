#!/usr/bin/env python3
"""Behavioral tests for the exact-head release-tag preflight."""

from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
VERIFY = ROOT / "scripts" / "verify-release-tag-head.sh"


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


class VerifyReleaseTagHeadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.repo = Path(self.tempdir.name)
        git(self.repo, "init", "-q")
        git(self.repo, "config", "user.name", "Release Test")
        git(self.repo, "config", "user.email", "release-test@example.invalid")
        (self.repo / "payload.txt").write_text("first\n", encoding="utf-8")
        git(self.repo, "add", "payload.txt")
        git(self.repo, "commit", "-q", "-m", "first")
        self.first_commit = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "tag", "-a", "v1.2.3", "-m", "v1.2.3")
        self.annotated_tag_object = git(self.repo, "rev-parse", "v1.2.3")

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def verify(
        self, tag_ref: str, main_ref: str = "HEAD", mode: str = "exact"
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(VERIFY), tag_ref, main_ref, "v1.2.3", mode],
            cwd=self.repo,
            capture_output=True,
            text=True,
        )

    def test_accepts_exact_direct_commit(self) -> None:
        result = self.verify(self.first_commit)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_accepts_exact_annotated_tag_object(self) -> None:
        result = self.verify(self.annotated_tag_object)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_stale_ancestor(self) -> None:
        (self.repo / "payload.txt").write_text("second\n", encoding="utf-8")
        git(self.repo, "add", "payload.txt")
        git(self.repo, "commit", "-q", "-m", "second")

        result = self.verify(self.annotated_tag_object)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be main's exact HEAD", result.stderr)

    def test_rejects_unknown_mode_even_when_commits_match(self) -> None:
        result = self.verify(self.annotated_tag_object, mode="bogus")
        self.assertEqual(result.returncode, 2)
        self.assertIn("Unknown release tag-head verification mode", result.stderr)

    def test_draft_recovery_accepts_immutable_ancestor_after_main_advances(self) -> None:
        (self.repo / "payload.txt").write_text("second\n", encoding="utf-8")
        git(self.repo, "add", "payload.txt")
        git(self.repo, "commit", "-q", "-m", "second")

        result = self.verify(self.annotated_tag_object, mode="allow-main-advance")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("advanced to descendant", result.stdout)

    def test_draft_recovery_rejects_diverged_main(self) -> None:
        git(self.repo, "checkout", "-q", "--orphan", "replacement-main")
        git(self.repo, "rm", "-q", "-f", "payload.txt")
        (self.repo / "replacement.txt").write_text("replacement\n", encoding="utf-8")
        git(self.repo, "add", "replacement.txt")
        git(self.repo, "commit", "-q", "-m", "replacement")

        result = self.verify(self.annotated_tag_object, mode="allow-main-advance")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("only permits main to advance as a descendant", result.stderr)


if __name__ == "__main__":
    unittest.main()
