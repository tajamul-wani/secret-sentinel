"""Tests for Secret Sentinel scanner engine."""

import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from secret_sentinel.scanner import (
    _is_ignored,
    _line_has_secret_keyword,
    _normalize_path,
    _sanitize_source_path,
    get_git_root,
    get_staged_content,
    get_staged_paths,
    scan_paths,
    scan_staged_files,
    scan_text,
    summarize_issues,
)

# Test dummy tokens constructed via concatenation to prevent false triggers in remote secret scanners
DUMMY_AWS = "AKIA" + "1234567890ABCDEF"
DUMMY_GOOGLE = "AIza" + "SyD-dummyGoogleKeyPattern_123456789"
DUMMY_STRIPE = "pk_test_" + "123456789012345678901234"
DUMMY_GITHUB = "ghp_" + "123456789012345678901234567890123456"
DUMMY_SLACK = "xoxb-" + "1234567890-abcdefghij"
DUMMY_JWT = "eyJ" + "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisSignature123"
DUMMY_TWILIO = "SK" + "1234567890abcdef" + "1234567890abcdef"
DUMMY_OPENAI = "sk-proj-" + "1234567890abcdefghijklmnopqrstuvwxyz123456"
DUMMY_ANTHROPIC = "sk-ant-" + "1234567890abcdefghijklmnopqrstuvwxyz123456"
DUMMY_HUGGINGFACE = "hf_" + "1234567890abcdefghijklmnopqrstuvwx"
DUMMY_PYPI = "pypi-AgEIcHlwaS5vcmc" + "1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdef"
DUMMY_NPM = "npm_" + "1234567890abcdefghijklmnopqrstuvwxyz"
DUMMY_PRIVATE_KEY = "-----BEGIN " + "RSA " + "PRIVATE KEY-----"
DUMMY_DB_URI = "postgresql://admin:" + "superSecretPass123" + "@db.example.com:5432/mydb"


class TestScanner(unittest.TestCase):
    """Test suite for secret detection patterns and scanner operations."""

    def test_scan_text_detects_aws_key(self) -> None:
        """Detect AWS access keys."""
        content = f'aws_key = "{DUMMY_AWS}"\n'
        issues = scan_text(content, "config.py")
        self.assertTrue(any(i["matcher"] == "AWS Secret Access Key" for i in issues))

    def test_scan_text_detects_google_key(self) -> None:
        """Detect Google API keys."""
        content = f'g_key = "{DUMMY_GOOGLE}"\n'
        issues = scan_text(content, "api.py")
        self.assertTrue(any(i["matcher"] == "Google API Key" for i in issues))

    def test_scan_text_detects_stripe_key(self) -> None:
        """Detect Stripe API keys."""
        content = f'stripe = "{DUMMY_STRIPE}"\n'
        issues = scan_text(content, "billing.py")
        self.assertTrue(any(i["matcher"] == "Stripe API Key" for i in issues))

    def test_scan_text_detects_github_token(self) -> None:
        """Detect GitHub personal access tokens."""
        content = f'gh = "{DUMMY_GITHUB}"\n'
        issues = scan_text(content, "ci.py")
        self.assertTrue(any(i["matcher"] == "GitHub Token" for i in issues))

    def test_scan_text_detects_slack_token(self) -> None:
        """Detect Slack tokens."""
        content = f'slack = "{DUMMY_SLACK}"\n'
        issues = scan_text(content, "slack.py")
        self.assertTrue(any(i["matcher"] == "Slack Token" for i in issues))

    def test_scan_text_detects_jwt(self) -> None:
        """Detect JWT tokens."""
        content = f'token = "{DUMMY_JWT}"\n'
        issues = scan_text(content, "auth.py")
        self.assertTrue(any(i["matcher"] == "JWT" for i in issues))

    def test_scan_text_detects_twilio_key(self) -> None:
        """Detect Twilio keys."""
        content = f'twilio = "{DUMMY_TWILIO}"\n'
        issues = scan_text(content, "sms.py")
        self.assertTrue(any(i["matcher"] == "Twilio Secret Key" for i in issues))

    def test_scan_text_detects_private_key(self) -> None:
        """Detect private key headers."""
        content = f'{DUMMY_PRIVATE_KEY}\nMIIEowIBAAKCAQEA0...\n'
        issues = scan_text(content, "id_rsa")
        self.assertTrue(any(i["matcher"] == "Private Key" for i in issues))

    def test_scan_text_detects_database_uri(self) -> None:
        """Detect database connection URIs with embedded passwords."""
        content = f'DATABASE_URL = "{DUMMY_DB_URI}"\n'
        issues = scan_text(content, "env.py")
        self.assertTrue(any(i["matcher"] == "Database Connection URI" for i in issues))

    def test_scan_text_detects_openai_key(self) -> None:
        """Detect OpenAI API keys."""
        content = f'OPENAI_API_KEY = "{DUMMY_OPENAI}"\n'
        issues = scan_text(content, "ai.py")
        self.assertTrue(any(i["matcher"] == "OpenAI API Key" for i in issues))

    def test_scan_text_detects_anthropic_key(self) -> None:
        """Detect Anthropic API keys."""
        content = f'ANTHROPIC_KEY = "{DUMMY_ANTHROPIC}"\n'
        issues = scan_text(content, "claude.py")
        self.assertTrue(any(i["matcher"] == "Anthropic API Key" for i in issues))

    def test_scan_text_detects_huggingface_token(self) -> None:
        """Detect HuggingFace access tokens."""
        content = f'HF_TOKEN = "{DUMMY_HUGGINGFACE}"\n'
        issues = scan_text(content, "model.py")
        self.assertTrue(any(i["matcher"] == "HuggingFace Token" for i in issues))

    def test_scan_text_detects_pypi_token(self) -> None:
        """Detect PyPI API tokens."""
        content = f'PYPI_TOKEN = "{DUMMY_PYPI}"\n'
        issues = scan_text(content, "publish.py")
        self.assertTrue(any(i["matcher"] == "PyPI API Token" for i in issues))

    def test_scan_text_detects_npm_token(self) -> None:
        """Detect NPM access tokens."""
        content = f'NPM_TOKEN = "{DUMMY_NPM}"\n'
        issues = scan_text(content, "package.py")
        self.assertTrue(any(i["matcher"] == "NPM Access Token" for i in issues))

    def test_scan_text_inline_ignore_hash(self) -> None:
        """Inline # secret-sentinel: ignore should suppress the finding."""
        content = f'aws_key = "{DUMMY_AWS}"  # secret-sentinel: ignore\n'
        issues = scan_text(content, "test.py")
        self.assertEqual(len(issues), 0)

    def test_scan_text_inline_ignore_c_style(self) -> None:
        """Inline // secret-sentinel: ignore should suppress the finding."""
        content = f'const key = "{DUMMY_AWS}"; // secret-sentinel: ignore\n'
        issues = scan_text(content, "test.js")
        self.assertEqual(len(issues), 0)

    def test_scan_text_disable_next_line(self) -> None:
        """Directive # secret-sentinel: disable-next-line should suppress only next line."""
        content = (
            f'# secret-sentinel: disable-next-line\n'
            f'aws_key1 = "{DUMMY_AWS}"\n'
            f'aws_key2 = "{DUMMY_AWS}"\n'
        )
        issues = scan_text(content, "test.py")
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["line"], 3)

    def test_scan_text_detects_generic_secret(self) -> None:
        """Detect generic secret assignments."""
        content = 'api_key: "abcdef1234567890_super_secret"\n'
        issues = scan_text(content, "settings.yml")
        self.assertTrue(any(i["matcher"] == "Generic Secret Assignment" for i in issues))

    def test_scan_text_detects_high_entropy_string(self) -> None:
        """Detect high entropy strings paired with secret keywords."""
        content = 'secret_token = "K9zXwQ7pL2vM5yB8tR4cE1aD3fG6hJ0n"\n'
        issues = scan_text(content, "secure.py")
        self.assertTrue(any(i["matcher"] == "High entropy string" for i in issues))

    def test_scan_text_ignores_clean_code(self) -> None:
        """Clean code without secret patterns or entropy should return no issues."""
        content = 'def add(a: int, b: int) -> int:\n    return a + b\n'
        issues = scan_text(content, "math_utils.py")
        self.assertEqual(len(issues), 0)

    def test_summarize_issues_redacts_secrets(self) -> None:
        """Findings summary must redact secrets and never output raw values."""
        secret_val = DUMMY_AWS
        issues = [
            {
                "source": "auth.py",
                "line": 12,
                "matcher": "AWS Secret Access Key",
                "value": secret_val,
                "snippet": f'aws_key = "{secret_val}"',
                "confidence": "high",
                "severity": "CRITICAL",
            }
        ]
        summary = summarize_issues(issues)
        self.assertIn("auth.py:12 [AWS Secret Access Key] - aws_key = \"[REDACTED]\"", summary)
        self.assertNotIn(secret_val, summary)

    def test_summarize_issues_empty(self) -> None:
        """Summarizing empty issues should return an empty string."""
        self.assertEqual(summarize_issues([]), "")

    def test_is_ignored_rules(self) -> None:
        """Verify glob matching in _is_ignored."""
        ignores = ["__pycache__/*", "*.tmp", "build/*"]
        self.assertTrue(_is_ignored("build/app.py", ignores))
        self.assertTrue(_is_ignored("data.tmp", ignores))
        self.assertFalse(_is_ignored("src/main.py", ignores))

    def test_sanitize_source_path(self) -> None:
        """Verify repo-relative path sanitization."""
        repo_root = "/home/user/project"
        full_path = "/home/user/project/src/index.py"
        sanitized = _sanitize_source_path(full_path, repo_root)
        self.assertEqual(sanitized, "src/index.py")

        external_path = "/var/log/syslog"
        self.assertEqual(_sanitize_source_path(external_path, repo_root), "/var/log/syslog")

    def test_normalize_path(self) -> None:
        """Path separators should be converted to forward slashes."""
        self.assertEqual(_normalize_path("folder\\sub\\file.py"), "folder/sub/file.py")

    def test_line_has_secret_keyword(self) -> None:
        """Keyword detection should identify credential keywords."""
        self.assertTrue(_line_has_secret_keyword("my_secret_token = '...'"))
        self.assertTrue(_line_has_secret_keyword("API_KEY: '...'"))
        self.assertFalse(_line_has_secret_keyword("counter = 42"))

    def test_scan_paths_disk(self) -> None:
        """Scan directory and files on disk."""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_clean = os.path.join(tmpdir, "clean.py")
            with open(file_clean, "w", encoding="utf-8") as f:
                f.write("x = 10\n")

            file_secret = os.path.join(tmpdir, "secret.py")
            with open(file_secret, "w", encoding="utf-8") as f:
                f.write(f'token = "{DUMMY_GITHUB}"\n')

            # Binary file should be skipped
            file_bin = os.path.join(tmpdir, "binary.bin")
            with open(file_bin, "wb") as f:
                f.write(b"\x00\x01\x02\x03\x04")

            issues = scan_paths([tmpdir])
            self.assertTrue(any(i["matcher"] == "GitHub Token" for i in issues))

    def test_scan_paths_single_file(self) -> None:
        """Scan directly targeted file path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            target_file = os.path.join(tmpdir, "app.py")
            with open(target_file, "w", encoding="utf-8") as f:
                f.write(f'key = "{DUMMY_AWS}"\n')

            issues = scan_paths([target_file])
            self.assertEqual(len(issues), 1)

            # Ignored file check
            ignored_issues = scan_paths([target_file], ignore_globs=["*app.py"])
            self.assertEqual(len(ignored_issues), 0)

            # Nonexistent file check
            nonexistent = scan_paths([os.path.join(tmpdir, "missing.py")])
            self.assertEqual(len(nonexistent), 0)

    def test_scan_staged_files(self) -> None:
        """Scan staged files using mocked git output."""
        with patch("secret_sentinel.scanner.get_staged_paths", return_value=["app.py"]):
            with patch(
                "secret_sentinel.scanner.get_staged_content",
                return_value=f'api_key = "{DUMMY_AWS}"\n',
            ):
                issues = scan_staged_files()
                self.assertTrue(any(i["matcher"] == "AWS Secret Access Key" for i in issues))
                self.assertEqual(issues[0]["source"], "app.py")

    def test_scan_staged_files_none_content(self) -> None:
        """Staged files returning None content should be safely skipped."""
        with patch("secret_sentinel.scanner.get_staged_paths", return_value=["app.bin"]):
            with patch("secret_sentinel.scanner.get_staged_content", return_value=None):
                issues = scan_staged_files()
                self.assertEqual(len(issues), 0)

    def test_git_helpers(self) -> None:
        """Test git utility commands."""
        with patch("secret_sentinel.scanner._run_git_command") as mock_git:
            mock_git.return_value = MagicMock(returncode=0, stdout="/path/to/repo\n")
            self.assertEqual(get_git_root(), "/path/to/repo")

            mock_git.return_value = MagicMock(returncode=1, stdout="")
            self.assertIsNone(get_git_root())

            mock_git.return_value = MagicMock(returncode=0, stdout="file1.py\nfile2.py\n")
            self.assertEqual(get_staged_paths(), ["file1.py", "file2.py"])

            mock_git.return_value = MagicMock(returncode=1, stdout="")
            self.assertEqual(get_staged_paths(), [])

            mock_git.return_value = MagicMock(returncode=0, stdout=b"content")
            self.assertEqual(get_staged_content("file1.py"), "content")

            mock_git.return_value = MagicMock(returncode=1, stdout=b"")
            self.assertIsNone(get_staged_content("file1.py"))


if __name__ == "__main__":
    unittest.main()
