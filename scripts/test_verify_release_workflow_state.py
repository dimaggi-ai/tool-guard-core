#!/usr/bin/env python3
"""Behavioral tests for release workflow state and tag immutability."""

from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / "scripts" / "verify-release-workflow-state.sh"
IMMUTABLE = ROOT / "scripts" / "verify-release-tag-immutable.sh"


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


class VerifyReleaseWorkflowStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.repo = Path(self.tempdir.name)
        git(self.repo, "init", "-q")
        git(self.repo, "config", "user.name", "Release State Test")
        git(self.repo, "config", "user.email", "release-state@example.invalid")
        scripts = self.repo / "scripts"
        scripts.mkdir()
        (scripts / "verify-release-tag-head.sh").write_bytes(
            (ROOT / "scripts" / "verify-release-tag-head.sh").read_bytes()
        )
        self.first = self.commit("first")
        git(self.repo, "tag", "-a", "v1.2.3", "-m", "v1.2.3")

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def commit(self, value: str) -> str:
        (self.repo / "payload.txt").write_text(value + "\n", encoding="utf-8")
        git(self.repo, "add", "payload.txt")
        git(self.repo, "commit", "-q", "-m", value)
        return git(self.repo, "rev-parse", "HEAD")

    def verify_state(
        self, event_ref: str, attempt: str, state: str
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(STATE), event_ref, "HEAD", "v1.2.3", attempt, state],
            cwd=self.repo,
            capture_output=True,
            text=True,
        )

    def verify_immutable(self, event_ref: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(IMMUTABLE), event_ref, "refs/tags/v1.2.3", "v1.2.3"],
            cwd=self.repo,
            capture_output=True,
            text=True,
        )

    def test_first_attempt_requires_exact_main_head(self) -> None:
        result = self.verify_state(self.first, "1", "missing")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.commit("second")
        result = self.verify_state(self.first, "1", "missing")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be main's exact HEAD", result.stderr)

    def test_draft_retry_accepts_descendant_main(self) -> None:
        self.commit("second")
        result = self.verify_state(self.first, "2", "draft")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("advanced to descendant", result.stdout)

    def test_retry_without_draft_still_requires_exact_head(self) -> None:
        self.commit("second")
        result = self.verify_state(self.first, "2", "missing")
        self.assertNotEqual(result.returncode, 0)

    def test_retry_rejects_public_release(self) -> None:
        result = self.verify_state(self.first, "2", "public")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("already public", result.stderr)

    def test_draft_retry_rejects_diverged_main(self) -> None:
        git(self.repo, "checkout", "-q", "--orphan", "replacement-main")
        git(self.repo, "rm", "-q", "-f", "payload.txt")
        self.commit("replacement")
        result = self.verify_state(self.first, "2", "draft")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("only permits main to advance as a descendant", result.stderr)

    def test_moved_tag_is_rejected_by_preflight_and_finalizer(self) -> None:
        second = self.commit("second")
        git(self.repo, "tag", "-f", "-a", "v1.2.3", "-m", "moved", second)
        state_result = self.verify_state(self.first, "2", "draft")
        self.assertNotEqual(state_result.returncode, 0)
        self.assertIn("moved from workflow commit", state_result.stderr)
        immutable_result = self.verify_immutable(self.first)
        self.assertNotEqual(immutable_result.returncode, 0)
        self.assertIn("refusing publication", immutable_result.stderr)

    def test_finalizer_accepts_unchanged_tag(self) -> None:
        result = self.verify_immutable(self.first)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
