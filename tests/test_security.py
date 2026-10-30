"""Security-specific verification tests mandated by Project Protocol.

These tests ensure that secrets, credentials, tokens, and sensitive system
paths are never leaked in findings reports, history records, or error output.
"""

import json
import tempfile
import unittest

from secret_sentinel.history import ScanHistory
from secret_sentinel.scanner import scan_text, summarize_issues
from secret_sentinel.utils import mask_secret, sanitize_snippet

# Construct tokens dynamically so they are never stored as contiguous raw secrets in git diffs
DUMMY_AWS = "AKIA" + "1234567890ABCDEF"
DUMMY_GOOGLE = "AIza" + "SyD-1234567890abcdefghijklmnopqrs12"
DUMMY_STRIPE = "pk_test_" + "123456789012345678901234"
DUMMY_GITHUB = "ghp_" + "123456789012345678901234567890123456"
DUMMY_SLACK = "xoxb-" + "1234567890-" + "abcdefghij"
DUMMY_TWILIO = "SK" + "1234567890abcdef" + "1234567890abcdef"


class TestSecurityAndLeakPrevention(unittest.TestCase):
    """Rigorous security checks ensuring zero secret or credential leakage."""

    def test_scanner_summary_never_exposes_plain_secret(self) -> None:
        """Verify findings summaries never contain the raw secret."""
        secrets_to_test = [
            (DUMMY_AWS, "AWS Secret Access Key"),
            (DUMMY_GOOGLE, "Google API Key"),
            (DUMMY_STRIPE, "Stripe API Key"),
            (DUMMY_GITHUB, "GitHub Token"),
            (DUMMY_SLACK, "Slack Token"),
            (DUMMY_TWILIO, "Twilio Secret Key"),
        ]

        for secret, expected_matcher in secrets_to_test:
            code = f'credentials = "{secret}"\n'
            issues = scan_text(code, "config.py")
            self.assertTrue(len(issues) >= 1)

            summary = summarize_issues(issues)
            # The raw secret string MUST NOT be in the summary
            self.assertNotIn(
                secret,
                summary,
                f"Security failure: Raw secret {secret} leaked in summary output!",
            )
            # The summary must contain the redacted placeholder
            self.assertIn("[REDACTED]", summary)

    def test_scan_history_never_records_secret_values(self) -> None:
        """Scan history records must store metadata only, never raw secret values."""
        raw_secret = DUMMY_GITHUB
        issues = [
            {
                "matcher": "GitHub Token",
                "source": "ci.py",
                "line": 15,
                "value": raw_secret,
                "snippet": f'token = "{raw_secret}"',
                "confidence": "high",
            }
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            history = ScanHistory(tmpdir)
            history.record_scan(issues, scan_type="manual", status="blocked")

            records = history.get_history()
            self.assertEqual(len(records), 1)

            # Convert record to JSON string and verify raw secret is absent
            serialized = json.dumps(records[0])
            self.assertNotIn(
                raw_secret,
                serialized,
                "Security failure: Raw secret found inside history record!",
            )

    def test_mask_secret_is_complete(self) -> None:
        """Masked secret must not leak prefix, suffix, or partial key data."""
        secret = "secret_credential_string_12345"
        masked = mask_secret(secret)
        self.assertEqual(masked, "[REDACTED]")
        self.assertNotIn(secret[:4], masked)
        self.assertNotIn(secret[-4:], masked)

    def test_sanitize_snippet_removes_all_occurrences(self) -> None:
        """All occurrences of a secret in a snippet line must be redacted."""
        secret = "duplicate_secret_value_xyz"
        snippet = f'a = "{secret}"; b = "{secret}"'
        sanitized = sanitize_snippet(snippet, secret)
        self.assertNotIn(secret, sanitized)
        self.assertEqual(sanitized.count("[REDACTED]"), 2)


if __name__ == "__main__":
    unittest.main()
