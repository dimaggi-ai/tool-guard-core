#!/usr/bin/env python3
"""Normalize release-controlled gzip metadata in Python source archives."""

from __future__ import annotations

import argparse
import io
import gzip
from pathlib import Path
import tarfile
import time
import zipfile


def normalize_sdist(path: Path, epoch: int) -> None:
    if not 0 <= epoch <= 0xFFFFFFFF:
        raise ValueError("epoch must fit the gzip header's uint32 mtime")

    try:
        source = tarfile.open(path, mode="r:gz")
    except (tarfile.TarError, OSError) as error:
        raise ValueError(f"{path} is not a valid gzip-compressed tar archive") from error

    tar_buffer = io.BytesIO()
    with source, tarfile.open(
        fileobj=tar_buffer, mode="w", format=tarfile.PAX_FORMAT
    ) as target:
        for member in sorted(source.getmembers(), key=lambda item: item.name):
            parts = Path(member.name).parts
            if Path(member.name).is_absolute() or ".." in parts:
                raise ValueError(f"unsafe sdist member path {member.name!r}")
            if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
                raise ValueError(f"unsupported sdist member type for {member.name!r}")

            normalized = tarfile.TarInfo(member.name)
            normalized.type = member.type
            normalized.mode = member.mode
            normalized.mtime = epoch
            normalized.uid = 0
            normalized.gid = 0
            normalized.uname = ""
            normalized.gname = ""
            normalized.linkname = member.linkname
            normalized.size = member.size if member.isfile() else 0
            payload = source.extractfile(member) if member.isfile() else None
            target.addfile(normalized, payload)

    gzip_buffer = io.BytesIO()
    with gzip.GzipFile(
        filename="", mode="wb", fileobj=gzip_buffer, mtime=epoch
    ) as compressed:
        compressed.write(tar_buffer.getvalue())
    normalized_bytes = gzip_buffer.getvalue()

    # Validate the complete replacement before touching the release artifact.
    try:
        with tarfile.open(fileobj=io.BytesIO(normalized_bytes), mode="r:gz") as check:
            check.getmembers()
    except tarfile.TarError as error:
        raise ValueError("normalized sdist failed validation") from error
    path.write_bytes(normalized_bytes)


def normalize_wheel(path: Path, epoch: int) -> None:
    if epoch < 0:
        raise ValueError("epoch must be non-negative")
    # ZIP timestamps cannot represent dates before 1980-01-01.
    timestamp = time.gmtime(max(epoch, 315_532_800))[:6]

    try:
        with zipfile.ZipFile(path, mode="r") as source:
            entries = [(info, source.read(info.filename)) for info in source.infolist()]
    except (zipfile.BadZipFile, OSError) as error:
        raise ValueError(f"{path} is not a valid wheel ZIP archive") from error

    output = io.BytesIO()
    with zipfile.ZipFile(
        output, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as target:
        for original, payload in entries:
            normalized = zipfile.ZipInfo(original.filename, date_time=timestamp)
            normalized.compress_type = zipfile.ZIP_DEFLATED
            normalized.create_system = 3
            mode = (original.external_attr >> 16) & 0o777
            if not mode:
                mode = 0o755 if original.is_dir() else 0o644
            normalized.external_attr = mode << 16
            target.writestr(normalized, payload, compress_type=zipfile.ZIP_DEFLATED)

    normalized_bytes = output.getvalue()
    try:
        with zipfile.ZipFile(io.BytesIO(normalized_bytes), mode="r") as check:
            if check.testzip() is not None:
                raise ValueError("normalized wheel failed CRC validation")
    except zipfile.BadZipFile as error:
        raise ValueError("normalized wheel failed validation") from error
    path.write_bytes(normalized_bytes)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("dist_dir", type=Path)
    parser.add_argument("--epoch", required=True, type=int)
    args = parser.parse_args()

    sdists = sorted(args.dist_dir.glob("*.tar.gz"))
    wheels = sorted(args.dist_dir.glob("*.whl"))
    if len(sdists) != 1 or len(wheels) != 1:
        raise SystemExit(
            f"expected one wheel and one sdist in {args.dist_dir}; "
            f"found {len(wheels)} wheel(s), {len(sdists)} sdist(s)"
        )
    try:
        normalize_sdist(sdists[0], args.epoch)
        normalize_wheel(wheels[0], args.epoch)
    except ValueError as error:
        raise SystemExit(str(error)) from error
    print(
        f"OK: normalized {wheels[0].name} and {sdists[0].name} "
        f"to SOURCE_DATE_EPOCH={args.epoch}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
