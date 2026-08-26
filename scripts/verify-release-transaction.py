#!/usr/bin/env python3
"""Static guardrails for the tag-triggered release transaction."""

from pathlib import Path
import re


root = Path(__file__).resolve().parents[1]
goreleaser = (root / ".goreleaser.yaml").read_text(encoding="utf-8")
workflow = (root / ".github/workflows/release.yml").read_text(encoding="utf-8")
action_refs = re.findall(r"^\s*uses:\s*([^\s#]+)", workflow, flags=re.MULTILINE)
release_job = workflow.split("\n  release:\n", maxsplit=1)[-1].split(
    "\n  publish-python:\n", maxsplit=1
)[0]
finalizer = workflow.split("\n  finalize-release:\n", maxsplit=1)[-1]
active_finalizer = "\n".join(
    line for line in finalizer.splitlines() if not line.lstrip().startswith("#")
)
verify_index = active_finalizer.find("python3 scripts/verify_pypi_release.py")
promote_command = 'gh release edit "${TAG}" --draft=false'
promote_index = active_finalizer.find(promote_command)
final_state_command = 'test "$(gh release view "${TAG}" --json isDraft --jq \'.isDraft\')" = "false"'
final_state_index = active_finalizer.find(final_state_command)

checks = {
    "GoReleaser stages a draft": "  draft: true" in goreleaser,
    "GoReleaser reruns reuse the staged draft": "  use_existing_draft: true" in goreleaser,
    "GoReleaser reruns replace existing release assets": "  replace_existing_artifacts: true" in goreleaser,
    "preflight rejects tags unsupported by signature verification": "Release tags must be stable semver (vN.N.N)" in workflow,
    "release refuses to mutate an already-public release": "refusing to rebuild or push release artifacts" in release_job,
    "PyPI retries are idempotent": "          skip-existing: true" in workflow,
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
    "only finalizer actively promotes the release": active_finalizer.count(promote_command) == 1,
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
