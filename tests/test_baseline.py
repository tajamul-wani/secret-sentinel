"""Tests for secret-free finding baselines."""

import json
import tempfile
import unittest
from pathlib import Path

from secret_sentinel.baseline import ScanBaseline

DUMMY_AWS = "AKIA" + "1234567890ABCDEF"


class TestScanBaseline(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.key_patch = unittest.mock.patch.dict(
            "os.environ",
            {"SECRET_SENTINEL_BASELINE_KEY": "test-key-" + "x" * 32},
        )
        self.key_patch.start()
        self.baseline = ScanBaseline(self.temp_dir.name)
        self.issue = {
            "source": "config.py",
            "matcher": "AWS Secret Access Key",
            "value": DUMMY_AWS,
        }

    def tearDown(self) -> None:
        self.key_patch.stop()
        self.temp_dir.cleanup()

    def test_save_does_not_store_secret_values(self) -> None:
        self.baseline.save([self.issue])

        contents = self.baseline.path.read_text(encoding="utf-8")
        self.assertNotIn(DUMMY_AWS, contents)
        self.assertEqual(len(self.baseline.load()), 1)

    def test_filter_suppresses_known_finding_and_keeps_new_finding(self) -> None:
        self.baseline.save([self.issue])
        new_issue = dict(self.issue, value="different-" + DUMMY_AWS)

        issues, suppressed = self.baseline.filter_issues([self.issue, new_issue])

        self.assertEqual(issues, [new_issue])
        self.assertEqual(suppressed, 1)

    def test_moved_line_does_not_change_fingerprint(self) -> None:
        self.baseline.save([self.issue])
        moved_issue = dict(self.issue, line=99, snippet="different context")

        issues, suppressed = self.baseline.filter_issues([moved_issue])

        self.assertEqual(issues, [])
        self.assertEqual(suppressed, 1)

    def test_baseline_key_must_match_to_suppress_findings(self) -> None:
        self.baseline.save([self.issue])
        with unittest.mock.patch.dict(
            "os.environ", {"SECRET_SENTINEL_BASELINE_KEY": "other-key-" + "y" * 32}
        ):
            other_key_baseline = ScanBaseline(self.temp_dir.name)

        issues, suppressed = other_key_baseline.filter_issues([self.issue])

        self.assertEqual(issues, [self.issue])
        self.assertEqual(suppressed, 0)

    def test_load_rejects_invalid_baseline(self) -> None:
        self.baseline.path.parent.mkdir(parents=True)
        self.baseline.path.write_text(
            json.dumps({"version": 1, "fingerprints": ["not-a-fingerprint"]}),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(ValueError, "Invalid fingerprint list"):
            self.baseline.load()

    def test_fingerprint_requires_finding_identity(self) -> None:
        with self.assertRaisesRegex(ValueError, "missing source, matcher, or value"):
            self.baseline.fingerprint({"source": "config.py"})

    def test_baseline_requires_strong_key(self) -> None:
        with unittest.mock.patch.dict(
            "os.environ", {"SECRET_SENTINEL_BASELINE_KEY": "too-short"}
        ):
            with self.assertRaisesRegex(ValueError, "must be set to at least 32 bytes"):
                ScanBaseline(self.temp_dir.name)


if __name__ == "__main__":
    unittest.main()
