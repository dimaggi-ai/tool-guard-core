from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from verify_pypi_release import VerificationError, local_distributions, verify_metadata


class VerifyPyPIReleaseTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dist_dir = Path(self.temp_dir.name)
        self.wheel = self.dist_dir / "toolguard_core-0.8.0-py3-none-any.whl"
        self.sdist = self.dist_dir / "toolguard_core-0.8.0.tar.gz"
        self.wheel.write_bytes(b"wheel bytes")
        self.sdist.write_bytes(b"sdist bytes")
        self.expected = local_distributions(self.dist_dir)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def metadata(self) -> dict[str, object]:
        return {
            "info": {"version": "0.8.0"},
            "urls": [
                {"filename": name, "digests": {"sha256": digest}}
                for name, digest in self.expected.items()
            ],
        }

    def test_accepts_exact_files_and_digests(self) -> None:
        verify_metadata(self.metadata(), self.expected, "0.8.0")

    def test_rejects_wrong_digest(self) -> None:
        metadata = self.metadata()
        metadata["urls"][0]["digests"]["sha256"] = hashlib.sha256(b"wrong").hexdigest()
        with self.assertRaisesRegex(VerificationError, "digest differs"):
            verify_metadata(metadata, self.expected, "0.8.0")

    def test_rejects_wrong_or_extra_filename(self) -> None:
        metadata = self.metadata()
        metadata["urls"][0]["filename"] = "wrong.whl"
        with self.assertRaisesRegex(VerificationError, "filenames differ"):
            verify_metadata(metadata, self.expected, "0.8.0")

    def test_rejects_wrong_version(self) -> None:
        metadata = self.metadata()
        metadata["info"]["version"] = "0.7.0"
        with self.assertRaisesRegex(VerificationError, "metadata version"):
            verify_metadata(metadata, self.expected, "0.8.0")

    def test_rejects_duplicate_filename(self) -> None:
        metadata = self.metadata()
        metadata["urls"].append(metadata["urls"][0])
        with self.assertRaisesRegex(VerificationError, "repeats filename"):
            verify_metadata(metadata, self.expected, "0.8.0")


if __name__ == "__main__":
    unittest.main()
