#!/usr/bin/env python3
"""Hash every binary and release archive listed by GoReleaser."""

import hashlib
import json
from pathlib import Path
import sys


def manifest(dist: Path) -> str:
    artifacts = json.loads((dist / "artifacts.json").read_text())
    selected = {}
    kinds = set()
    for artifact in artifacts:
        if artifact["type"] not in ("Binary", "Archive"):
            continue
        path = Path(artifact["path"])
        # GoReleaser paths are relative to its source checkout.
        relative = path.relative_to("dist")
        if ".." in relative.parts or str(relative) in selected:
            raise ValueError(f"invalid or duplicate artifact path: {path}")
        selected[str(relative)] = hashlib.sha256((dist / relative).read_bytes()).hexdigest()
        kinds.add(artifact["type"])
    if kinds != {"Binary", "Archive"}:
        raise ValueError("expected both binaries and archives in artifacts.json")
    return "".join(f"{digest}  {name}\n" for name, digest in sorted(selected.items()))


if __name__ == "__main__":
    print(manifest(Path(sys.argv[1])), end="")
