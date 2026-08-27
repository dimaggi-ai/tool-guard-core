#!/usr/bin/env python3
"""Static guardrails for the tag-triggered release transaction."""

from pathlib import Path
import re


root = Path(__file__).resolve().parents[1]
goreleaser = (root / ".goreleaser.yaml").read_text(encoding="utf-8")
workflow = (root / ".github/workflows/release.yml").read_text(encoding="utf-8")
runbook = (root / "RELEASING.md").read_text(encoding="utf-8")
action_refs = re.findall(r"^\s*uses:\s*([^\s#]+)", workflow, flags=re.MULTILINE)


def region(text: str, start: str, end: str | None = None) -> str:
    """Return a required delimited region; never widen silently on a miss."""
    if text.count(start) != 1:
        return ""
    value = text.split(start, maxsplit=1)[1]
    if end is not None:
        if value.count(end) != 1:
            return ""
        value = value.split(end, maxsplit=1)[0]
    return value


def step(job: str, name: str) -> str:
    marker = f"      - name: {name}\n"
    if job.count(marker) != 1:
        return ""
    value = job.split(marker, maxsplit=1)[1]
    return re.split(r"\n      - |\n\n  ", value, maxsplit=1)[0]


def steps(job: str) -> list[str]:
    """Return every YAML step block, including unnamed action steps."""
    return [
        part
        for part in re.split(r"(?=^      - (?:name|uses):)", job, flags=re.MULTILINE)
        if re.match(r"^      - (?:name|uses):", part)
    ]


def matching_step_indices(items: list[str], needle: str) -> list[int]:
    return [index for index, item in enumerate(items) if needle in item]


def active(text: str) -> str:
    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )


preflight = region(workflow, "\n  preflight:\n", "\n  verify:\n")
release_job = region(workflow, "\n  release:\n", "\n  publish-python:\n")
python_publish_job = region(
    workflow, "\n  publish-python:\n", "\n  finalize-release:\n"
)
finalizer = region(workflow, "\n  finalize-release:\n")
resolve_step = step(preflight, "Resolve release state")
preflight_step = step(preflight, "Verify new tag or safe draft recovery")
release_tag_step = step(release_job, "Verify release tag before artifact publication")
publish_step = step(finalizer, "Publish verified GitHub Release")
python_tag_step = step(python_publish_job, "Verify release tag before PyPI publication")
release_steps = steps(release_job)
python_publish_steps = steps(python_publish_job)
artifact_verifier_name = "      - name: Verify release tag before artifact publication\n"
pypi_verifier_name = "      - name: Verify release tag before PyPI publication\n"
goreleaser_indices = matching_step_indices(
    release_steps, "goreleaser/goreleaser-action@"
)
artifact_verifier_indices = matching_step_indices(
    release_steps, artifact_verifier_name
)
pypi_publisher_indices = matching_step_indices(
    python_publish_steps, "pypa/gh-action-pypi-publish@"
)
pypi_verifier_indices = matching_step_indices(
    python_publish_steps, pypi_verifier_name
)
active_finalizer = active(finalizer)

resolve_body = """        id: release-state
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GH_REPO: ${{ github.repository }}
        run: |
          set -euo pipefail
          release_state=missing
          if [ "${GITHUB_RUN_ATTEMPT}" -gt 1 ]; then
            if release_draft="$(gh release view "${GITHUB_REF_NAME}" --json isDraft --jq '.isDraft' 2>/dev/null)"; then
              if [ "${release_draft}" = "true" ]; then
                release_state=draft
              elif [ "${release_draft}" = "false" ]; then
                release_state=public
              fi
            fi
          fi
          echo "state=${release_state}" >> "${GITHUB_OUTPUT}"
"""
preflight_body = """        run: |
          set -euo pipefail
          git fetch origin main --quiet
          git fetch origin "refs/tags/${GITHUB_REF_NAME}:refs/remotes/origin/release-preflight-tag" --force --quiet
          bash scripts/verify-release-workflow-state.sh \\
            "${GITHUB_SHA}" origin/main "${GITHUB_REF_NAME}" \\
            "${GITHUB_RUN_ATTEMPT}" "${{ steps.release-state.outputs.state }}" \\
            refs/remotes/origin/release-preflight-tag
"""
final_tag_gate = """          set -euo pipefail
          git fetch origin "refs/tags/${TAG}:refs/remotes/origin/release-tag-check" --force --quiet
          bash scripts/verify-release-tag-immutable.sh \\
            "${GITHUB_SHA}" refs/remotes/origin/release-tag-check "${TAG}"
"""
pypi_tag_gate = """        env:
          TAG: ${{ github.ref_name }}
        run: |
          set -euo pipefail
          git fetch origin "refs/tags/${TAG}:refs/remotes/origin/release-pypi-tag-check" --force --quiet
          bash scripts/verify-release-tag-immutable.sh \\
            "${GITHUB_SHA}" refs/remotes/origin/release-pypi-tag-check "${TAG}"
"""
artifact_tag_gate = """        env:
          TAG: ${{ github.ref_name }}
        run: |
          set -euo pipefail
          git fetch origin "refs/tags/${TAG}:refs/remotes/origin/release-artifact-tag-check" --force --quiet
          bash scripts/verify-release-tag-immutable.sh \\
            "${GITHUB_SHA}" refs/remotes/origin/release-artifact-tag-check "${TAG}"
"""
goreleaser_publisher = """- name: Run GoReleaser
        uses: goreleaser/goreleaser-action@e435ccd777264be153ace6237001ef4d979d3a7a # v6
        with:
          distribution: goreleaser
          version: "~> v2"
          args: release --clean
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}"""
pypi_publisher = """- name: Publish with PyPI trusted publishing
        uses: pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33 # release/v1, reviewed 2026-08-26
        with:
          packages-dir: dist/python/
          skip-existing: true"""
promote_command = 'gh release edit "${TAG}" --draft=false'
verify_index = active_finalizer.find("python3 scripts/verify_pypi_release.py")
promote_index = active_finalizer.find(promote_command)
immutable_index = publish_step.find(final_tag_gate)
final_state_command = 'test "$(gh release view "${TAG}" --json isDraft --jq \'.isDraft\')" = "false"'
final_state_index = active_finalizer.find(final_state_command)
local_tag_index = runbook.find('git tag -a vX.Y.Z -m "Tool Guard Core vX.Y.Z"')
local_version_check_index = runbook.find(
    "python scripts/verify-python-dist.py dist/python --expected-version X.Y.Z"
)
tag_push_index = runbook.find("git push origin vX.Y.Z")

checks = {
    "release workflow job boundaries are structurally present": bool(
        preflight and release_job and python_publish_job and finalizer
    ),
    "GoReleaser stages a draft": "  draft: true" in goreleaser,
    "GoReleaser reruns reuse the staged draft": "  use_existing_draft: true" in goreleaser,
    "GoReleaser reruns replace existing release assets": "  replace_existing_artifacts: true" in goreleaser,
    "preflight rejects tags unsupported by signature verification": "Release tags must be stable semver (vN.N.N)" in workflow,
    "preflight resolves draft state in an exact guarded step": (
        resolve_step.rstrip() == resolve_body.rstrip()
    ),
    "preflight verifier is an exact unguarded final command": (
        preflight_step.rstrip() == preflight_body.rstrip()
    ),
    "finalizer immutable-tag gate is unguarded and adjacent to publication": (
        publish_step.count(final_tag_gate) == 1
        and publish_step.startswith("        env:\n")
        and publish_step.split("        run: |\n", maxsplit=1)[-1].startswith(final_tag_gate)
        and 0 <= immutable_index < publish_step.find(promote_command)
    ),
    "GoReleaser publication has an exact adjacent immutable-tag gate": (
        len(artifact_verifier_indices) == 1
        and len(goreleaser_indices) == 1
        and goreleaser_indices[0] == artifact_verifier_indices[0] + 1
        and release_steps[artifact_verifier_indices[0]].split(
            artifact_verifier_name, maxsplit=1
        )[-1].rstrip() == artifact_tag_gate.rstrip()
        and active(release_steps[goreleaser_indices[0]]).strip()
        == goreleaser_publisher
        and active(workflow).count("goreleaser/goreleaser-action@") == 1
    ),
    "PyPI publication has an exact adjacent immutable-tag gate": (
        len(pypi_verifier_indices) == 1
        and len(pypi_publisher_indices) == 1
        and pypi_publisher_indices[0] == pypi_verifier_indices[0] + 1
        and python_publish_steps[pypi_verifier_indices[0]].split(
            pypi_verifier_name, maxsplit=1
        )[-1].rstrip() == pypi_tag_gate.rstrip()
        and active(python_publish_steps[pypi_publisher_indices[0]]).strip()
        == pypi_publisher
        and active(workflow).count("pypa/gh-action-pypi-publish@") == 1
        and "      contents: read" in python_publish_job
    ),
    "release refuses to mutate an already-public release": "refusing to rebuild or push release artifacts" in release_job,
    "PyPI retries are idempotent": "          skip-existing: true" in workflow,
    "Python release builds pin source timestamps": "SOURCE_DATE_EPOCH" in workflow,
    "Python archives are clean-rebuild reproducible": "bash scripts/verify-python-reproducible.sh" in workflow,
    "Python release build frontends are pinned": "build==1.5.0 twine==7.0.0" in workflow,
    "runbook verifies tag-derived Python version before publishing tag": (
        0 <= local_tag_index < local_version_check_index < tag_push_index
    ),
    "finalizer waits for artifacts and PyPI": "    needs: [release, publish-python]" in workflow,
    "checkout-free finalizer has repository context": "      GH_REPO: ${{ github.repository }}" in workflow,
    "first finalizer attempt rejects unexpected public state": "was already public on the first finalizer attempt" in workflow,
    "promotion retry accepts a previously completed edit": "was already promoted by an earlier attempt" in workflow,
    "finalizer downloads the release's Python distributions": (
        "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093" in finalizer
        and "          name: python-dist" in finalizer
        and "          path: dist/python" in finalizer
    ),
    "finalizer verifies PyPI filenames and digests": "python3 scripts/verify_pypi_release.py" in active_finalizer,
    "only finalizer actively promotes the release": (
        active(workflow).count(promote_command) == 1
        and active(publish_step).count(promote_command) == 1
    ),
    "promotion occurs after PyPI verification": 0 <= verify_index < promote_index,
    "final public-state check occurs after promotion": 0 <= promote_index < final_state_index,
    "OIDC download action is SHA-pinned": "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093" in workflow,
    "PyPI publisher action is SHA-pinned": "pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33" in workflow,
    "every third-party release action is SHA-pinned": all(
        ref.startswith("./") or re.fullmatch(r"[^@]+@[0-9a-f]{40}", ref)
        for ref in action_refs
    ),
}

failed = [name for name, ok in checks.items() if not ok]
if failed:
    raise SystemExit("release transaction guard failed: " + "; ".join(failed))

print("release transaction guard: OK")
