"""Tests for Secret Sentinel report formatters (Text, JSON, SARIF)."""

import json
import unittest

from secret_sentinel.formatters import (
    format_json,
    format_sarif,
    format_suppression_audit_json,
    format_suppression_audit_sarif,
    format_suppression_audit_text,
    format_text,
)
from secret_sentinel.risk_scoring import SeverityLevel

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
        """Text format should give a concise positive message for a clean scan."""
        result = format_text([])
        self.assertEqual(result, "All clear! No potential secrets found.")

    def test_format_text_with_issues(self) -> None:
        """Text format should list issues with secrets redacted."""
        result = format_text(self.sample_issues)
        self.assertIn("[REDACTED]", result)
        self.assertNotIn(DUMMY_AWS, result)
        self.assertIn("CRITICAL", result)
        self.assertIn("Severity summary: CRITICAL: 1", result)
        self.assertIn("Next: verify each finding", result)
        self.assertIn("Possible false positive?", result)
        self.assertIn("Why flagged: A built-in secret pattern matched.", result)
        self.assertIn("Confidence: high.", result)
        self.assertIn("Deactivate the access key in IAM", result)
        self.assertIn("Review CloudTrail", result)
        self.assertIn("remove the exposed value from repository history", result)

    def test_format_text_sorts_findings_by_severity(self) -> None:
        """Text output should summarize severities and list urgent findings first."""
        medium_issue = {
            "source": "app.py",
            "line": 2,
            "matcher": "High entropy string",
            "value": "randomStr1234567890",
            "snippet": 'token = "randomStr1234567890"',
            "severity": "MEDIUM",
        }
        result = format_text([medium_issue, self.sample_issues[0]])
        self.assertIn("Severity summary: CRITICAL: 1, MEDIUM: 1", result)
        self.assertLess(result.index("[CRITICAL]"), result.index("[MEDIUM]"))
        self.assertNotIn(medium_issue["value"], result)

    def test_format_text_explains_entropy_findings(self) -> None:
        """Text output should explain entropy signals and their confidence."""
        issue = {
            "source": "app.py",
            "line": 1,
            "matcher": "High entropy string",
            "value": "randomStr1234567890",
            "snippet": 'token = "randomStr1234567890"',
            "confidence": "medium",
            "reason": "entropy",
            "severity": "MEDIUM",
        }
        result = format_text([issue])
        self.assertIn(
            "Why flagged: A high-entropy string was assigned "
            "to a secret-related field.",
            result,
        )
        self.assertIn("Confidence: medium.", result)
        self.assertNotIn(issue["value"], result)

    def test_format_text_includes_commit_provenance(self) -> None:
        """Text output should include abbreviated commit provenance when present."""
        issue = dict(self.sample_issues[0], commit="1234567890abcdef")
        result = format_text([issue])
        self.assertIn("(commit 1234567890ab)", result)
        self.assertNotIn(DUMMY_AWS, result)

    def test_format_text_below_fail_on(self) -> None:
        """Text format below fail_on threshold should indicate warnings allowed."""
        medium_issue = [{
            "source": "app.py",
            "line": 1,
            "matcher": "High entropy string",
            "value": "randomStr1234567890",
            "snippet": 'x = "randomStr1234567890"',
            "severity": "MEDIUM",
        }]
        result = format_text(medium_issue, fail_on=SeverityLevel.HIGH)
        self.assertIn("below failure threshold", result)
        self.assertNotIn("Commit blocked", result)

    def test_format_json_below_fail_on(self) -> None:
        """JSON format below fail_on threshold should set status to warning."""
        medium_issue = [{
            "source": "app.py",
            "line": 1,
            "matcher": "High entropy string",
            "value": "randomStr1234567890",
            "snippet": 'x = "randomStr1234567890"',
            "severity": "MEDIUM",
        }]
        data = json.loads(format_json(medium_issue, fail_on=SeverityLevel.HIGH))
        self.assertEqual(data["status"], "warning")

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
        self.assertEqual(data["issues"][0]["reason"], "pattern")
        self.assertEqual(
            data["issues"][0]["explanation"],
            "A built-in secret pattern matched.",
        )
        self.assertIn("Deactivate the access key in IAM", data["issues"][0]["remediation"][0])
        self.assertNotIn(DUMMY_AWS, raw_json)

    def test_format_json_sanitizes_unknown_detection_reason(self) -> None:
        """Unknown reason metadata should not leak into JSON reports."""
        issue = dict(
            self.sample_issues[0],
            confidence=DUMMY_AWS,
            reason=DUMMY_AWS,
        )
        raw_json = format_json([issue])
        data = json.loads(raw_json)

        self.assertNotIn(DUMMY_AWS, raw_json)
        self.assertEqual(data["issues"][0]["confidence"], "not specified")
        self.assertEqual(data["issues"][0]["reason"], "unknown")
        self.assertEqual(
            data["issues"][0]["explanation"],
            "A configured detector identified a potential secret.",
        )

    def test_format_json_includes_baseline_suppressed_count(self) -> None:
        data = json.loads(format_json([], baseline_suppressed=2))
        self.assertEqual(data["baseline_suppressed"], 2)

    def test_format_json_includes_commit_provenance(self) -> None:
        """JSON output should preserve commit provenance."""
        issue = dict(self.sample_issues[0], commit="1234567890abcdef")
        data = json.loads(format_json([issue]))
        self.assertEqual(data["issues"][0]["commit"], "1234567890abcdef")

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
        self.assertEqual(result["properties"]["confidence"], "high")
        self.assertEqual(result["properties"]["reason"], "pattern")
        self.assertIn("A built-in secret pattern matched.", result["message"]["text"])
        self.assertIn("Confidence: high.", result["message"]["text"])
        self.assertEqual(
            result["properties"]["explanation"],
            "A built-in secret pattern matched.",
        )
        self.assertIn("Deactivate the access key in IAM", result["properties"]["remediation"][0])

    def test_format_sarif_uses_configured_custom_severity(self) -> None:
        issue = dict(
            self.sample_issues[0],
            matcher="Company API Token",
            severity="CRITICAL",
        )
        data = json.loads(format_sarif([issue]))

        self.assertEqual(data["runs"][0]["results"][0]["level"], "error")

    def test_format_sarif_includes_commit_provenance(self) -> None:
        """SARIF output should preserve commit provenance in result properties."""
        issue = dict(self.sample_issues[0], commit="1234567890abcdef")
        data = json.loads(format_sarif([issue]))
        result = data["runs"][0]["results"][0]
        self.assertEqual(result["properties"]["commit"], "1234567890abcdef")

    def test_format_sarif_includes_baseline_suppressed_count(self) -> None:
        data = json.loads(format_sarif([], baseline_suppressed=2))
        self.assertEqual(data["runs"][0]["properties"]["baselineSuppressed"], 2)

    def test_format_suppression_audit_text_empty_and_findings(self) -> None:
        """Audit text should clearly report empty and review-needed results."""
        self.assertEqual(
            format_suppression_audit_text([]),
            "No inline suppression directives found.",
        )
        report = format_suppression_audit_text(
            [
                {
                    "source": "src/config.py",
                    "line": 4,
                    "target_line": 5,
                    "statuses": ["missing-reason", "unused"],
                }
            ]
        )
        self.assertIn("src/config.py:4 -> line 5", report)
        self.assertIn("[MISSING REASON, UNUSED]", report)
        self.assertIn("1 suppression(s) need review", report)

    def test_format_suppression_audit_json_is_secret_free(self) -> None:
        """JSON reports include only audit metadata, never source text or values."""
        raw_secret = "fixture-secret-value"
        report = format_suppression_audit_json(
            [
                {
                    "source": "src/config.py",
                    "line": 4,
                    "target_line": 4,
                    "statuses": ["missing-expiry"],
                    "snippet": raw_secret,
                    "value": raw_secret,
                }
            ]
        )

        data = json.loads(report)
        self.assertEqual(data["status"], "review")
        self.assertEqual(data["total_suppressions"], 1)
        self.assertEqual(data["needs_review"], 1)
        self.assertEqual(data["suppressions"][0]["statuses"], ["missing-expiry"])
        self.assertNotIn(raw_secret, report)
        self.assertNotIn("snippet", data["suppressions"][0])

    def test_format_suppression_audit_sarif_includes_locations_and_status(self) -> None:
        """SARIF audit output should map statuses to safe source-line diagnostics."""
        raw_secret = "fixture-secret-value"
        report = format_suppression_audit_sarif(
            [
                {
                    "source": "src/config.py",
                    "line": 4,
                    "target_line": 5,
                    "statuses": ["missing-reason", "unused"],
                    "snippet": raw_secret,
                    "value": raw_secret,
                },
                {
                    "source": "src/other.py",
                    "line": 8,
                    "target_line": 8,
                    "statuses": ["active"],
                },
            ]
        )

        data = json.loads(report)
        run = data["runs"][0]
        self.assertEqual(data["version"], "2.1.0")
        self.assertEqual(len(run["results"]), 2)
        self.assertEqual(run["results"][0]["ruleId"], "suppression-review")
        self.assertEqual(run["results"][0]["level"], "warning")
        self.assertEqual(
            run["results"][0]["locations"][0]["physicalLocation"]["region"][
                "startLine"
            ],
            4,
        )
        self.assertEqual(run["results"][0]["properties"]["targetLine"], 5)
        self.assertEqual(run["results"][1]["ruleId"], "suppression-active")
        self.assertEqual(run["results"][1]["level"], "note")
        self.assertNotIn(raw_secret, report)

    def test_format_suppression_audit_sarif_empty(self) -> None:
        """SARIF audit output for a clean repository has no results."""
        data = json.loads(format_suppression_audit_sarif([]))
        self.assertEqual(data["version"], "2.1.0")
        self.assertEqual(data["runs"][0]["results"], [])

    def test_unknown_matcher_gets_generic_remediation(self) -> None:
        issue = dict(self.sample_issues[0], matcher="Organization Custom Token")
        data = json.loads(format_json([issue]))
        steps = data["issues"][0]["remediation"]
        self.assertTrue(any("revoke or rotate it with its issuer" in step for step in steps))


if __name__ == "__main__":
    unittest.main()
