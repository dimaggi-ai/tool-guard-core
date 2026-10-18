#!/usr/bin/env python3
"""Require a verified archive digest before generating its release SBOM."""

import hashlib
from pathlib import Path
import subprocess
import sys


def verify(manifest: Path, artifact: Path) -> None:
    entries = {}
    for line in manifest.read_text().splitlines():
        digest, name = line.split("  ", 1)
        if name in entries:
            raise ValueError(f"duplicate checksum entry: {name}")
        entries[name] = digest
    expected = entries.get(artifact.name)
    actual = hashlib.sha256(artifact.read_bytes()).hexdigest()
    if expected is None or actual != expected:
        raise ValueError(f"archive does not match clean rebuilds: {artifact.name}")
    print(f"Verified clean rebuild: {actual}  {artifact.name}", flush=True)


if __name__ == "__main__":
    manifest, artifact, document = sys.argv[1:]
    verify(Path(manifest), Path(artifact))
    subprocess.run(
        ["syft", artifact, "--output", f"spdx-json={document}", "--enrich", "all"],
        check=True,
    )
