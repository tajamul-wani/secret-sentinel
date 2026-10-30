"""Tests for AI validation module."""

import json
import unittest
from io import BytesIO
from unittest.mock import MagicMock, patch

from secret_sentinel.ai_validator import (
    _query_gemini,
    _query_ollama,
    _run_command,
    build_surrounding_snippet,
    validate_issue,
    validate_issues,
)


class TestAIValidator(unittest.TestCase):
    """Test suite for AI validation and fallback mechanisms."""

    def test_build_surrounding_snippet(self) -> None:
        """Snippet builder should extract surrounding context lines."""
        content = "line1\nline2\nline3\nline4\nline5\n"
        snippet = build_surrounding_snippet(content, line_number=3, context=1)
        self.assertIn("line2", snippet)
        self.assertIn("line3", snippet)
        self.assertIn("line4", snippet)
        self.assertNotIn("line1", snippet)

    def test_build_surrounding_snippet_boundaries(self) -> None:
        """Snippet builder should handle first and last line gracefully."""
        content = "line1\nline2\nline3\n"
        snippet_top = build_surrounding_snippet(content, line_number=1, context=2)
        self.assertIn("line1", snippet_top)

        snippet_bottom = build_surrounding_snippet(content, line_number=3, context=2)
        self.assertIn("line3", snippet_bottom)

    def test_validate_issue_fallback_high_confidence(self) -> None:
        """Fallback without AI should preserve high confidence issues."""
        issue = {"value": "some_secret", "confidence": "high"}
        with patch("secret_sentinel.ai_validator._query_ollama", return_value=None):
            with patch("secret_sentinel.ai_validator._query_gemini", return_value=None):
                self.assertTrue(validate_issue(issue, "surrounding code"))

    def test_validate_issue_fallback_medium_confidence(self) -> None:
        """Fallback without AI should reject low/medium confidence issues if AI unavailable."""
        issue = {"value": "entropy_string", "confidence": "medium"}
        with patch("secret_sentinel.ai_validator._query_ollama", return_value=None):
            with patch("secret_sentinel.ai_validator._query_gemini", return_value=None):
                self.assertFalse(validate_issue(issue, "surrounding code"))

    def test_validate_issue_ai_marks_false_positive(self) -> None:
        """AI returning FALSE_POSITIVE should cause validation to return False."""
        issue = {"value": "mock_token", "confidence": "high"}
        with patch("secret_sentinel.ai_validator._query_ollama", return_value="FALSE_POSITIVE"):
            self.assertFalse(validate_issue(issue, "surrounding code"))

    def test_validate_issue_ai_confirms_real_secret(self) -> None:
        """AI returning REAL_SECRET should cause validation to return True."""
        issue = {"value": "real_token", "confidence": "medium"}
        with patch("secret_sentinel.ai_validator._query_ollama", return_value="REAL_SECRET"):
            self.assertTrue(validate_issue(issue, "surrounding code"))

    def test_validate_issues_filtering(self) -> None:
        """validate_issues should filter out false positives."""
        issues = [
            {"value": "mock_key", "line": 1, "confidence": "high"},
            {"value": "real_key", "line": 2, "confidence": "high"},
        ]
        content = "mock_key_line\nreal_key_line\n"

        def mock_validate(issue, surrounding):
            return issue["value"] == "real_key"

        with patch("secret_sentinel.ai_validator.validate_issue", side_effect=mock_validate):
            verified = validate_issues(issues, "test.py", content)
            self.assertEqual(len(verified), 1)
            self.assertEqual(verified[0]["value"], "real_key")

    def test_query_gemini_without_api_key(self) -> None:
        """Querying Gemini without GEMINI_API_KEY should safely return None."""
        with patch.dict("os.environ", {}, clear=True):
            self.assertIsNone(_query_gemini("test prompt"))

    def test_query_gemini_success(self) -> None:
        """Querying Gemini with API key and valid response should return text."""
        mock_response_data = {
            "candidates": [
                {
                    "content": {
                        "parts": [{"text": "REAL_SECRET"}]
                    }
                }
            ]
        }
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(mock_response_data).encode("utf-8")
        mock_response.__enter__.return_value = mock_response

        with patch.dict("os.environ", {"GEMINI_API_KEY": "fake_key_for_test"}):
            with patch("urllib.request.urlopen", return_value=mock_response):
                result = _query_gemini("test prompt")
                self.assertEqual(result, "REAL_SECRET")

    def test_query_ollama_success(self) -> None:
        """Querying Ollama with exit code 0 should return stripped stdout."""
        mock_proc = MagicMock(returncode=0, stdout="REAL_SECRET\n")
        with patch("secret_sentinel.ai_validator._run_command", return_value=mock_proc):
            self.assertEqual(_query_ollama("test prompt"), "REAL_SECRET")

    def test_query_ollama_not_found(self) -> None:
        """Querying Ollama when binary does not exist should return None."""
        with patch("secret_sentinel.ai_validator._run_command", return_value=None):
            self.assertIsNone(_query_ollama("test prompt"))

    def test_run_command_exception(self) -> None:
        """_run_command should handle OSError gracefully."""
        with patch("subprocess.run", side_effect=FileNotFoundError):
            self.assertIsNone(_run_command(["nonexistent"]))


if __name__ == "__main__":
    unittest.main()
