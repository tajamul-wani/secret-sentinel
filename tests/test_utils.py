"""Tests for Secret Sentinel utility functions."""

import unittest

from secret_sentinel.utils import (
    is_text_bytes,
    mask_secret,
    sanitize_snippet,
    shannon_entropy,
)


class TestUtils(unittest.TestCase):
    """Test suite for utility helper functions."""

    def test_shannon_entropy_empty(self) -> None:
        """Shannon entropy of empty string should be 0.0."""
        self.assertEqual(shannon_entropy(""), 0.0)

    def test_shannon_entropy_low(self) -> None:
        """Repeated characters should have near-zero entropy."""
        self.assertAlmostEqual(shannon_entropy("aaaaaa"), 0.0, places=3)

    def test_shannon_entropy_high(self) -> None:
        """Diverse character strings should have high entropy."""
        self.assertGreater(shannon_entropy("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"), 4.0)

    def test_is_text_bytes_empty(self) -> None:
        """Empty bytes should be considered text."""
        self.assertTrue(is_text_bytes(b""))

    def test_is_text_bytes_ascii(self) -> None:
        """Standard ASCII bytes should be recognized as text."""
        self.assertTrue(is_text_bytes(b"hello world\n"))

    def test_is_text_bytes_null_byte(self) -> None:
        """Binary data with null byte should not be recognized as text."""
        self.assertFalse(is_text_bytes(b"hello\x00world"))

    def test_is_text_bytes_binary(self) -> None:
        """Arbitrary non-text binary bytes should not be recognized as text."""
        self.assertFalse(is_text_bytes(bytes([1, 2, 3, 4, 5])))

    def test_mask_secret(self) -> None:
        """Masking should return redacted placeholder."""
        self.assertEqual(mask_secret("super_secret_key_12345"), "[REDACTED]")

    def test_sanitize_snippet_replaces_secret(self) -> None:
        """Secret within a snippet should be safely replaced with [REDACTED]."""
        secret = "AIza" + "SyDdummyKey1234567890abcdefghijkl"
        snippet = f'api_key = "{secret}"'
        sanitized = sanitize_snippet(snippet, secret)
        self.assertEqual(sanitized, 'api_key = "[REDACTED]"')
        self.assertNotIn(secret, sanitized)

    def test_sanitize_snippet_empty_inputs(self) -> None:
        """Empty snippet or secret should return safely without error."""
        self.assertEqual(sanitize_snippet("", "key"), "")
        self.assertEqual(sanitize_snippet("code line", ""), "code line")


if __name__ == "__main__":
    unittest.main()
