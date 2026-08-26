from __future__ import annotations

import gzip
import io
import tempfile
import tarfile
import unittest
import zipfile
from pathlib import Path

from normalize_python_dist import normalize_sdist, normalize_wheel


class NormalizePythonDistTest(unittest.TestCase):
    def test_different_gzip_mtimes_normalize_to_identical_bytes(self) -> None:
        payload = b"deterministic tar payload"
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.tar.gz"
            second = Path(directory) / "second.tar.gz"
            self.write_sdist(first, payload, mtime=1, owner="first-user")
            self.write_sdist(second, payload, mtime=2, owner="second-user")

            normalize_sdist(first, 1_700_000_000)
            normalize_sdist(second, 1_700_000_000)

            self.assertEqual(first.read_bytes(), second.read_bytes())
            with tarfile.open(first, mode="r:gz") as archive:
                self.assertEqual(archive.extractfile("package/file.txt").read(), payload)
                member = archive.getmember("package/file.txt")
                self.assertEqual(member.mtime, 1_700_000_000)
                self.assertEqual(member.uid, 0)
                self.assertEqual(member.uname, "")

    def test_rejects_non_gzip_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.tar.gz"
            path.write_bytes(b"not gzip")
            with self.assertRaisesRegex(ValueError, "not a valid"):
                normalize_sdist(path, 1_700_000_000)

    def test_rejects_epoch_outside_gzip_range(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "archive.tar.gz"
            self.write_sdist(path, b"payload", mtime=0, owner="builder")
            with self.assertRaisesRegex(ValueError, "uint32"):
                normalize_sdist(path, 0x1_0000_0000)

    def test_different_wheel_timestamps_normalize_to_identical_bytes(self) -> None:
        payload = b"wheel payload"
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.whl"
            second = Path(directory) / "second.whl"
            self.write_wheel(first, payload, (2025, 1, 1, 0, 0, 0))
            self.write_wheel(second, payload, (2026, 1, 1, 0, 0, 0))

            normalize_wheel(first, 1_700_000_000)
            normalize_wheel(second, 1_700_000_000)

            self.assertEqual(first.read_bytes(), second.read_bytes())
            with zipfile.ZipFile(first) as archive:
                self.assertEqual(archive.read("toolguard/client.py"), payload)

    @staticmethod
    def write_sdist(path: Path, payload: bytes, mtime: int, owner: str) -> None:
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode="w") as archive:
            member = tarfile.TarInfo("package/file.txt")
            member.size = len(payload)
            member.mtime = mtime
            member.uname = owner
            archive.addfile(member, io.BytesIO(payload))
        with path.open("wb") as output:
            with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=mtime) as stream:
                stream.write(tar_buffer.getvalue())

    @staticmethod
    def write_wheel(
        path: Path, payload: bytes, timestamp: tuple[int, int, int, int, int, int]
    ) -> None:
        with zipfile.ZipFile(path, mode="w") as archive:
            member = zipfile.ZipInfo("toolguard/client.py", date_time=timestamp)
            archive.writestr(member, payload)


if __name__ == "__main__":
    unittest.main()
