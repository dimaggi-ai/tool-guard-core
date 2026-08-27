#!/usr/bin/env python3
"""Mutation tests for static release-workflow wiring guardrails."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class VerifyReleaseTransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.repo = Path(self.tempdir.name)
        (self.repo / "scripts").mkdir()
        (self.repo / ".github" / "workflows").mkdir(parents=True)
        for relative in (
            "scripts/verify-release-transaction.py",
            ".github/workflows/release.yml",
            ".goreleaser.yaml",
            "RELEASING.md",
        ):
            destination = self.repo / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    @property
    def workflow_path(self) -> Path:
        return self.repo / ".github" / "workflows" / "release.yml"

    def run_guard(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(self.repo / "scripts" / "verify-release-transaction.py")],
            cwd=self.repo,
            capture_output=True,
            text=True,
        )

    def test_current_wiring_passes(self) -> None:
        result = self.run_guard()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_exit_before_preflight_verifier_is_rejected(self) -> None:
        workflow = self.workflow_path.read_text(encoding="utf-8")
        workflow = workflow.replace(
            "          bash scripts/verify-release-workflow-state.sh",
            "          exit 0\n          bash scripts/verify-release-workflow-state.sh",
            1,
        )
        self.workflow_path.write_text(workflow, encoding="utf-8")
        result = self.run_guard()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("preflight delegates release-state behavior", result.stderr)

    def test_tag_check_after_publication_is_rejected(self) -> None:
        workflow = self.workflow_path.read_text(encoding="utf-8")
        workflow = workflow.replace(
            "          bash scripts/verify-release-tag-immutable.sh",
            "          echo deferred-tag-check",
            1,
        )
        workflow = workflow.replace(
            '            gh release edit "${TAG}" --draft=false',
            '            gh release edit "${TAG}" --draft=false\n'
            "            bash scripts/verify-release-tag-immutable.sh",
            1,
        )
        self.workflow_path.write_text(workflow, encoding="utf-8")
        result = self.run_guard()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("finalizer immutable-tag check occurs before publication", result.stderr)


if __name__ == "__main__":
    unittest.main()
