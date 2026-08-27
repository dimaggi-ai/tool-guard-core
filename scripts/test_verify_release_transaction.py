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
        self.assertIn("preflight verifier is an exact unguarded final command", result.stderr)
        self.assertIn("preflight verifier is an exact unguarded final command", result.stderr)

    def test_masked_preflight_verifier_is_rejected(self) -> None:
        workflow = self.workflow_path.read_text(encoding="utf-8")
        workflow = workflow.replace(
            '            refs/remotes/origin/release-preflight-tag',
            '            refs/remotes/origin/release-preflight-tag || true',
            1,
        )
        self.workflow_path.write_text(workflow, encoding="utf-8")
        result = self.run_guard()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("preflight verifier is an exact unguarded final command", result.stderr)
        self.assertIn("preflight verifier is an exact unguarded final command", result.stderr)

    def test_backgrounded_preflight_verifier_is_rejected(self) -> None:
        workflow = self.workflow_path.read_text(encoding="utf-8")
        workflow = workflow.replace(
            '            refs/remotes/origin/release-preflight-tag',
            '            refs/remotes/origin/release-preflight-tag &',
            1,
        )
        self.workflow_path.write_text(workflow, encoding="utf-8")
        result = self.run_guard()
        self.assertNotEqual(result.returncode, 0)

    def test_replaced_preflight_tag_fetch_is_rejected(self) -> None:
        workflow = self.workflow_path.read_text(encoding="utf-8")
        workflow = workflow.replace(
            '          git fetch origin "refs/tags/${GITHUB_REF_NAME}:refs/remotes/origin/release-preflight-tag" --force --quiet',
            "          echo skipped-tag-fetch",
            1,
        )
        self.workflow_path.write_text(workflow, encoding="utf-8")
        result = self.run_guard()
        self.assertNotEqual(result.returncode, 0)

    def test_replaced_release_draft_query_is_rejected(self) -> None:
        workflow = self.workflow_path.read_text(encoding="utf-8")
        workflow = workflow.replace(
            '            if release_draft="$(gh release view "${GITHUB_REF_NAME}" --json isDraft --jq \'.isDraft\' 2>/dev/null)"; then',
            "            if release_draft=true; then",
            1,
        )
        self.workflow_path.write_text(workflow, encoding="utf-8")
        result = self.run_guard()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("preflight resolves draft state in an exact guarded step", result.stderr)

    def test_release_state_override_is_rejected(self) -> None:
        workflow = self.workflow_path.read_text(encoding="utf-8")
        workflow = workflow.replace(
            '          echo "state=${release_state}" >> "${GITHUB_OUTPUT}"',
            '          release_state=draft\n'
            '          echo "state=${release_state}" >> "${GITHUB_OUTPUT}"',
            1,
        )
        self.workflow_path.write_text(workflow, encoding="utf-8")
        result = self.run_guard()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("preflight resolves draft state in an exact guarded step", result.stderr)

    def test_tag_check_after_publication_is_rejected(self) -> None:
        workflow = self.workflow_path.read_text(encoding="utf-8")
        workflow = workflow.replace(
            '          bash scripts/verify-release-tag-immutable.sh \\\n'
            '            "${GITHUB_SHA}" refs/remotes/origin/release-tag-check "${TAG}"',
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
        self.assertIn("finalizer immutable-tag gate is unguarded and adjacent to publication", result.stderr)

    def test_masked_final_tag_verifier_is_rejected(self) -> None:
        workflow = self.workflow_path.read_text(encoding="utf-8")
        workflow = workflow.replace(
            '            "${GITHUB_SHA}" refs/remotes/origin/release-tag-check "${TAG}"',
            '            "${GITHUB_SHA}" refs/remotes/origin/release-tag-check "${TAG}" || true',
            1,
        )
        self.workflow_path.write_text(workflow, encoding="utf-8")
        result = self.run_guard()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("finalizer immutable-tag gate is unguarded and adjacent to publication", result.stderr)

    def test_replaced_final_tag_fetch_is_rejected(self) -> None:
        workflow = self.workflow_path.read_text(encoding="utf-8")
        workflow = workflow.replace(
            '          git fetch origin "refs/tags/${TAG}:refs/remotes/origin/release-tag-check" --force --quiet',
            "          echo skipped-tag-fetch",
            1,
        )
        self.workflow_path.write_text(workflow, encoding="utf-8")
        result = self.run_guard()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("finalizer immutable-tag gate is unguarded", result.stderr)

    def test_promotion_outside_finalizer_is_rejected(self) -> None:
        workflow = self.workflow_path.read_text(encoding="utf-8")
        workflow = workflow.replace(
            "  publish-python:\n",
            '          gh release edit "${TAG}" --draft=false\n\n  publish-python:\n',
            1,
        )
        self.workflow_path.write_text(workflow, encoding="utf-8")
        result = self.run_guard()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("only finalizer actively promotes the release", result.stderr)

    def test_masked_pypi_tag_verifier_is_rejected(self) -> None:
        workflow = self.workflow_path.read_text(encoding="utf-8")
        workflow = workflow.replace(
            '            "${GITHUB_SHA}" refs/remotes/origin/release-pypi-tag-check "${TAG}"',
            '            "${GITHUB_SHA}" refs/remotes/origin/release-pypi-tag-check "${TAG}" || true',
            1,
        )
        self.workflow_path.write_text(workflow, encoding="utf-8")
        result = self.run_guard()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("PyPI publication has an exact adjacent immutable-tag gate", result.stderr)

    def test_pypi_tag_gate_after_publication_is_rejected(self) -> None:
        workflow = self.workflow_path.read_text(encoding="utf-8")
        marker = "      - name: Verify release tag before PyPI publication\n"
        start = workflow.index(marker)
        end = workflow.index("      - name: Publish with PyPI trusted publishing\n", start)
        gate = workflow[start:end]
        workflow = workflow[:start] + workflow[end:]
        insert = workflow.index("  finalize-release:\n")
        workflow = workflow[:insert] + gate + workflow[insert:]
        self.workflow_path.write_text(workflow, encoding="utf-8")
        result = self.run_guard()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("PyPI publication has an exact adjacent immutable-tag gate", result.stderr)

    def test_missing_job_boundary_is_rejected(self) -> None:
        workflow = self.workflow_path.read_text(encoding="utf-8")
        workflow = workflow.replace("\n  verify:\n", "\n  verify-ci:\n", 1)
        self.workflow_path.write_text(workflow, encoding="utf-8")
        result = self.run_guard()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("release workflow job boundaries are structurally present", result.stderr)


if __name__ == "__main__":
    unittest.main()
