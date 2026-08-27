#!/usr/bin/env python3
"""Validate the Python distribution without importing or executing it."""

from __future__ import annotations

import argparse
from email.parser import BytesParser
from pathlib import Path
import tarfile
import zipfile


def normalized_name(value: str) -> str:
    return value.lower().replace("_", "-").replace(".", "-")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("dist_dir", type=Path)
    parser.add_argument("--expected-version")
    args = parser.parse_args()

    wheels = sorted(args.dist_dir.glob("*.whl"))
    sdists = sorted(args.dist_dir.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise SystemExit(
            f"expected one wheel and one sdist in {args.dist_dir}; "
            f"found {len(wheels)} wheel(s), {len(sdists)} sdist(s)"
        )

    with zipfile.ZipFile(wheels[0]) as archive:
        metadata_paths = [
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        ]
        if len(metadata_paths) != 1:
            raise SystemExit(f"expected one wheel METADATA file; found {metadata_paths}")
        metadata = BytesParser().parsebytes(archive.read(metadata_paths[0]))
        names = set(archive.namelist())

    if normalized_name(metadata["Name"]) != "toolguard-core":
        raise SystemExit(f"distribution name is {metadata['Name']!r}, want 'toolguard-core'")
    if metadata["License-Expression"] != "Apache-2.0":
        raise SystemExit(
            f"license expression is {metadata['License-Expression']!r}, want 'Apache-2.0'"
        )
    if args.expected_version and metadata["Version"] != args.expected_version:
        raise SystemExit(
            f"distribution version is {metadata['Version']!r}, "
            f"want tag version {args.expected_version!r}"
        )
    for required in ("toolguard/__init__.py", "toolguard/client.py", "toolguard/types.py"):
        if required not in names:
            raise SystemExit(f"wheel is missing import package file {required}")
    if not any(name.endswith(".dist-info/licenses/LICENSE") for name in names):
        raise SystemExit("wheel is missing the Apache LICENSE file")

    with tarfile.open(sdists[0], "r:gz") as archive:
        members = archive.getnames()
    if not any(name.endswith("/pyproject.toml") for name in members):
        raise SystemExit("sdist is missing pyproject.toml")
    if not any(name.endswith("/toolguard/client.py") for name in members):
        raise SystemExit("sdist is missing toolguard/client.py")
    if not any(name.endswith("/LICENSE") for name in members):
        raise SystemExit("sdist is missing the Apache LICENSE file")

    print(
        f"OK: {wheels[0].name} and {sdists[0].name} "
        f"contain toolguard-core {metadata['Version']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
