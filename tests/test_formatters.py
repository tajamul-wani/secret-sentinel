"""Tests for Secret Sentinel report formatters (Text, JSON, SARIF)."""

import json
import unittest

from secret_sentinel.formatters import format_json, format_sarif, format_text

DUMMY_AWS = "AKIA" + "1234567890ABCDEF"


class TestFormatters(unittest.TestCase):
    """Test suite for findings report formatters."""

    def setUp(self) -> None:
        """Set up sample issue fixtures."""
        self.sample_issues = [
            {
                "source": "src/config.py",
                "line": 15,
                "matcher": "AWS Secret Access Key",
                "value": DUMMY_AWS,
                "snippet": f'aws_key = "{DUMMY_AWS}"',
                "confidence": "high",
                "reason": "pattern",
                "severity": "CRITICAL",
            }
        ]

    def test_format_text_clean(self) -> None:
        """Text format with no issues should report scan passed."""
        result = format_text([])
        self.assertEqual(result, "secret-sentinel scan passed.")

    def test_format_text_with_issues(self) -> None:
        """Text format should list issues with secrets redacted."""
        result = format_text(self.sample_issues)
        self.assertIn("[REDACTED]", result)
        self.assertNotIn(DUMMY_AWS, result)
        self.assertIn("CRITICAL", result)

    def test_format_json_clean(self) -> None:
        """JSON format with no issues should return passed status."""
        data = json.loads(format_json([]))
        self.assertEqual(data["status"], "passed")
        self.assertEqual(data["total_issues"], 0)
        self.assertEqual(data["issues"], [])

    def test_format_json_with_issues(self) -> None:
        """JSON format should return blocked status and redacted snippets."""
        raw_json = format_json(self.sample_issues)
        self.assertNotIn(DUMMY_AWS, raw_json)

        data = json.loads(raw_json)
        self.assertEqual(data["status"], "blocked")
        self.assertEqual(data["total_issues"], 1)
        self.assertEqual(data["overall_severity"], "CRITICAL")
        self.assertEqual(len(data["issues"]), 1)
        self.assertIn("[REDACTED]", data["issues"][0]["snippet"])

    def test_format_sarif_clean(self) -> None:
        """SARIF format should adhere to schema v2.1.0."""
        data = json.loads(format_sarif([]))
        self.assertEqual(data["version"], "2.1.0")
        self.assertIn("runs", data)
        self.assertEqual(len(data["runs"][0]["results"]), 0)

    def test_format_sarif_with_issues(self) -> None:
        """SARIF format should include rule definitions and redacted findings."""
        raw_sarif = format_sarif(self.sample_issues)
        self.assertNotIn(DUMMY_AWS, raw_sarif)

        data = json.loads(raw_sarif)
        run = data["runs"][0]
        self.assertEqual(len(run["results"]), 1)

        result = run["results"][0]
        self.assertEqual(result["ruleId"], "AWS Secret Access Key")
        self.assertEqual(result["level"], "error")
        self.assertEqual(
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "src/config.py",
        )
        self.assertEqual(
            result["locations"][0]["physicalLocation"]["region"]["startLine"],
            15,
        )


if __name__ == "__main__":
    unittest.main()

