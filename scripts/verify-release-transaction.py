#!/usr/bin/env python3
"""Static guardrails for the tag-triggered release transaction."""

from pathlib import Path
import re


root = Path(__file__).resolve().parents[1]
goreleaser = (root / ".goreleaser.yaml").read_text(encoding="utf-8")
workflow = (root / ".github/workflows/release.yml").read_text(encoding="utf-8")
action_refs = re.findall(r"^\s*uses:\s*([^\s#]+)", workflow, flags=re.MULTILINE)

checks = {
    "GoReleaser stages a draft": "  draft: true" in goreleaser,
    "PyPI retries are idempotent": "          skip-existing: true" in workflow,
    "finalizer waits for artifacts and PyPI": "    needs: [release, publish-python]" in workflow,
    "finalizer verifies the release is still a draft": 'is not a draft; refusing non-transactional promotion' in workflow,
    "finalizer verifies PyPI before promotion": "PyPI did not expose toolguard-core" in workflow,
    "only finalizer promotes the release": workflow.count('gh release edit "${TAG}" --draft=false') == 1,
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
