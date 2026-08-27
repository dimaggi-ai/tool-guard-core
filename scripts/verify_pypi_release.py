#!/usr/bin/env python3
"""Verify that PyPI exposes exactly the distributions built by this release."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any


class VerificationError(ValueError):
    """Raised when published PyPI metadata does not match local artifacts."""


def local_distributions(dist_dir: Path) -> dict[str, str]:
    files = sorted(
        path
        for path in dist_dir.iterdir()
        if path.is_file() and (path.suffix == ".whl" or path.name.endswith(".tar.gz"))
    )
    wheels = [path for path in files if path.suffix == ".whl"]
    sdists = [path for path in files if path.name.endswith(".tar.gz")]
    if len(wheels) != 1 or len(sdists) != 1:
        raise VerificationError(
            f"expected one wheel and one sdist in {dist_dir}; "
            f"found {len(wheels)} wheel(s), {len(sdists)} sdist(s)"
        )
    return {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in files
    }


def verify_metadata(
    metadata: dict[str, Any], expected: dict[str, str], expected_version: str
) -> None:
    info = metadata.get("info")
    if not isinstance(info, dict) or info.get("version") != expected_version:
        actual = info.get("version") if isinstance(info, dict) else None
        raise VerificationError(
            f"PyPI metadata version is {actual!r}, want {expected_version!r}"
        )

    urls = metadata.get("urls")
    if not isinstance(urls, list):
        raise VerificationError("PyPI metadata field 'urls' is not a list")

    published: dict[str, str] = {}
    for entry in urls:
        if not isinstance(entry, dict):
            raise VerificationError("PyPI metadata contains a non-object file entry")
        filename = entry.get("filename")
        digests = entry.get("digests")
        digest = digests.get("sha256") if isinstance(digests, dict) else None
        if not isinstance(filename, str) or not isinstance(digest, str):
            raise VerificationError("PyPI file entry is missing filename or SHA-256 digest")
        if filename in published:
            raise VerificationError(f"PyPI metadata repeats filename {filename!r}")
        published[filename] = digest.lower()

    if set(published) != set(expected):
        missing = sorted(set(expected) - set(published))
        extra = sorted(set(published) - set(expected))
        raise VerificationError(
            f"PyPI filenames differ from the release artifacts; missing={missing}, extra={extra}"
        )
    for filename, expected_digest in expected.items():
        if not hmac.compare_digest(published[filename], expected_digest):
            raise VerificationError(f"PyPI SHA-256 digest differs for {filename}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata", required=True, type=Path)
    parser.add_argument("--dist-dir", required=True, type=Path)
    parser.add_argument("--expected-version", required=True)
    args = parser.parse_args()

    with args.metadata.open(encoding="utf-8") as handle:
        metadata = json.load(handle)
    if not isinstance(metadata, dict):
        raise SystemExit("PyPI metadata root is not an object")

    try:
        expected = local_distributions(args.dist_dir)
        verify_metadata(metadata, expected, args.expected_version)
    except VerificationError as error:
        raise SystemExit(str(error)) from error

    print(
        f"OK: PyPI exposes toolguard-core {args.expected_version} with "
        f"the expected filenames and SHA-256 digests"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
