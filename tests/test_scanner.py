"""Tests for Secret Sentinel scanner engine."""

import os
import base64
import re
import subprocess
import tempfile
import unittest
from datetime import date, timedelta
from unittest.mock import MagicMock, patch

from secret_sentinel.config import CustomRule
from secret_sentinel.risk_scoring import SeverityLevel
from secret_sentinel.scanner import (
    ScanCoverage,
    _is_ignored,
    _normalize_path,
    _sanitize_source_path,
    audit_suppressions_in_repo,
    audit_suppressions_text,
    get_git_root,
    get_staged_content,
    get_staged_paths,
    scan_git_commit_range,
    scan_git_diff,
    scan_git_history,
    scan_git_push_updates,
    scan_paths,
    scan_staged_files,
    scan_text,
    summarize_issues,
)

# Test dummy tokens constructed via concatenation to prevent false triggers in remote secret scanners
DUMMY_AWS = "AKIA" + "1234567890ABCDEF"
DUMMY_AWS_SECRET = "AbCd1234" * 5
DUMMY_GOOGLE = "AIza" + "SyD-dummyGoogleKeyPattern_123456789"
DUMMY_STRIPE = "sk_test_" + "123456789012345678901234"
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

    @staticmethod
    def _run_git(repo_root: str, *args: str) -> str:
        """Run Git in a temporary test repository."""
        result = subprocess.run(
            ["git", *args],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()

    def _initialize_history_repo(self, repo_root: str) -> None:
        """Initialize a repository with an isolated test identity."""
        self._run_git(repo_root, "init", "-q")
        self._run_git(repo_root, "config", "user.name", "Test User")
        self._run_git(repo_root, "config", "user.email", "test@example.invalid")

    def _commit_file(self, repo_root: str, path: str, content: bytes) -> str:
        """Write and commit a test file, returning the new commit ID."""
        full_path = os.path.join(repo_root, path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "wb") as handle:
            handle.write(content)
        self._run_git(repo_root, "add", "--", path)
        self._run_git(repo_root, "commit", "-q", "-m", "test commit")
        return self._run_git(repo_root, "rev-parse", "HEAD")

    def test_scan_git_history_detects_secret_from_deleted_file(self) -> None:
        """History scan should find a secret even after its file is deleted."""
        with tempfile.TemporaryDirectory() as repo_root:
            self._initialize_history_repo(repo_root)
            first_commit = self._commit_file(
                repo_root,
                "config.py",
                f'aws_key = "{DUMMY_AWS}"\n'.encode(),
            )
            os.remove(os.path.join(repo_root, "config.py"))
            self._run_git(repo_root, "add", "--all")
            self._run_git(repo_root, "commit", "-q", "-m", "remove test file")

            issues = scan_git_history(repo_root)

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["source"], "config.py")
        self.assertEqual(issues[0]["commit"], first_commit)
        self.assertEqual(issues[0]["matcher"], "AWS Access Key ID")

    def test_scan_git_history_applies_custom_rules(self) -> None:
        """History scans should use configured detectors and their severity."""
        custom_rule = CustomRule(
            name="Company API Token",
            pattern=re.compile(r"\bcorp_[A-Za-z0-9]{20}\b"),
            severity=SeverityLevel.HIGH,
        )
        token = "corp_" + "b" * 20
        with tempfile.TemporaryDirectory() as repo_root:
            self._initialize_history_repo(repo_root)
            self._commit_file(
                repo_root,
                "settings.py",
                f'api_token = "{token}"\n'.encode(),
            )

            issues = scan_git_history(repo_root, custom_rules=[custom_rule])

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["matcher"], custom_rule.name)
        self.assertEqual(issues[0]["severity"], "HIGH")

    def test_scan_git_history_deduplicates_unchanged_blob(self) -> None:
        """Unchanged files across commits should not create duplicate findings."""
        with tempfile.TemporaryDirectory() as repo_root:
            self._initialize_history_repo(repo_root)
            self._commit_file(
                repo_root,
                "config.py",
                f'aws_key = "{DUMMY_AWS}"\n'.encode(),
            )
            self._commit_file(repo_root, "notes.txt", b"additional commit\n")

            issues = scan_git_history(repo_root)

        self.assertEqual(len(issues), 1)

    def test_scan_git_history_ignores_unreachable_local_branches(self) -> None:
        """History scan should not include commits outside current HEAD ancestry."""
        with tempfile.TemporaryDirectory() as repo_root:
            self._initialize_history_repo(repo_root)
            self._commit_file(repo_root, "README.txt", b"clean\n")
            head_branch = self._run_git(repo_root, "branch", "--show-current")
            self._run_git(repo_root, "checkout", "-q", "-b", "unmerged")
            self._commit_file(
                repo_root,
                "config.py",
                f'aws_key = "{DUMMY_AWS}"\n'.encode(),
            )
            self._run_git(repo_root, "checkout", "-q", head_branch)

            issues = scan_git_history(repo_root)

        self.assertEqual(issues, [])

    def test_scan_git_history_scans_all_refs_when_requested(self) -> None:
        """All-refs history mode should find secrets on unmerged branches."""
        with tempfile.TemporaryDirectory() as repo_root:
            self._initialize_history_repo(repo_root)
            self._commit_file(repo_root, "README.txt", b"clean\n")
            head_branch = self._run_git(repo_root, "branch", "--show-current")
            self._run_git(repo_root, "checkout", "-q", "-b", "unmerged")
            branch_commit = self._commit_file(
                repo_root,
                "config.py",
                f'aws_key = "{DUMMY_AWS}"\n'.encode(),
            )
            self._run_git(repo_root, "checkout", "-q", head_branch)

            issues = scan_git_history(repo_root, all_refs=True)

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["source"], "config.py")
        self.assertEqual(issues[0]["commit"], branch_commit)

    def test_scan_git_history_honors_ignore_globs_and_binary_content(self) -> None:
        """History scan should honor configured ignores and skip binary blobs."""
        with tempfile.TemporaryDirectory() as repo_root:
            self._initialize_history_repo(repo_root)
            self._commit_file(
                repo_root,
                "ignored/config.py",
                f'aws_key = "{DUMMY_AWS}"\n'.encode(),
            )
            self._commit_file(
                repo_root,
                "binary.dat",
                b"\x00" + f'aws_key = "{DUMMY_AWS}"\n'.encode(),
            )
            self._commit_file(
                repo_root,
                "src/config.py",
                f'aws_key = "{DUMMY_AWS}"\n'.encode(),
            )

            issues = scan_git_history(repo_root, ignore_globs=["ignored/*"])

        self.assertEqual([issue["source"] for issue in issues], ["src/config.py"])

    def test_git_scan_modes_honor_an_explicit_empty_ignore_list(self) -> None:
        """Empty ignore lists consistently include default-excluded paths."""
        with tempfile.TemporaryDirectory() as repo_root:
            self._initialize_history_repo(repo_root)
            self._commit_file(
                repo_root,
                "node_modules/initial.py",
                f'api_key = "{DUMMY_AWS}"\n'.encode(),
            )
            base_commit = self._run_git(repo_root, "rev-parse", "HEAD")
            staged_path = "node_modules/staged.py"
            full_path = os.path.join(repo_root, staged_path)
            with open(full_path, "w", encoding="utf-8") as handle:
                handle.write(f'api_key = "{DUMMY_AWS}"\n')
            self._run_git(repo_root, "add", "--", staged_path)

            history_issues = scan_git_history(repo_root, ignore_globs=[])
            staged_issues = scan_staged_files(
                repo_root=repo_root,
                ignore_globs=[],
            )
            diff_issues = scan_git_diff(
                base_commit,
                repo_root,
                ignore_globs=[],
            )

        history_sources = {issue["source"] for issue in history_issues}
        staged_sources = {issue["source"] for issue in staged_issues}
        diff_sources = {issue["source"] for issue in diff_issues}
        self.assertIn("node_modules/initial.py", history_sources)
        self.assertIn("node_modules/staged.py", staged_sources)
        self.assertIn("node_modules/staged.py", diff_sources)

    def test_scan_git_history_requires_repository_history(self) -> None:
        """History scan should report a clear error outside an initialized repo."""
        with tempfile.TemporaryDirectory() as repo_root:
            with self.assertRaisesRegex(RuntimeError, "Unable to read repository history"):
                scan_git_history(repo_root)

    def test_scan_git_push_updates_scans_only_commits_not_on_remote(self) -> None:
        """Pushed ranges omit findings already reachable from the remote SHA."""
        with tempfile.TemporaryDirectory() as repo_root:
            self._initialize_history_repo(repo_root)
            remote_commit = self._commit_file(
                repo_root, "existing.py", f'key = "{DUMMY_AWS}"\n'.encode()
            )
            pushed_commit = self._commit_file(
                repo_root, "notes.txt", b"new commit without findings\n"
            )
            updates = (
                f"refs/heads/main {pushed_commit} "
                f"refs/heads/main {remote_commit}\n"
            )

            issues = scan_git_push_updates(repo_root, updates)

        self.assertEqual(issues, [])

    def test_scan_git_push_updates_scans_new_branch_ancestry(self) -> None:
        """A new branch push scans its commits even without a remote SHA."""
        with tempfile.TemporaryDirectory() as repo_root:
            self._initialize_history_repo(repo_root)
            pushed_commit = self._commit_file(
                repo_root,
                "config with spaces.py",
                f'aws_key = "{DUMMY_AWS}"\n'.encode(),
            )
            updates = (
                f"refs/heads/new {pushed_commit} "
                f"refs/heads/new {'0' * 40}\n"
            )

            issues = scan_git_push_updates(repo_root, updates)

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["source"], "config with spaces.py")
        self.assertEqual(issues[0]["commit"], pushed_commit)

    def test_scan_git_push_updates_scans_merge_resolution_changes(self) -> None:
        """A finding introduced by merge resolution is scanned for a push."""
        with tempfile.TemporaryDirectory() as repo_root:
            self._initialize_history_repo(repo_root)
            self._commit_file(repo_root, "config.py", b"value = 'base'\n")
            main_branch = self._run_git(repo_root, "branch", "--show-current")
            self._run_git(repo_root, "checkout", "-q", "-b", "remote-side")
            remote_commit = self._commit_file(
                repo_root, "config.py", b"value = 'side'\n"
            )
            self._run_git(repo_root, "checkout", "-q", main_branch)
            self._commit_file(repo_root, "config.py", b"value = 'main'\n")
            merge = subprocess.run(
                ["git", "merge", "--no-ff", "-m", "test merge", "remote-side"],
                cwd=repo_root,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(merge.returncode, 0)
            with open(
                os.path.join(repo_root, "config.py"), "w", encoding="utf-8"
            ) as handle:
                handle.write(f'aws_key = "{DUMMY_AWS}"\n')
            self._run_git(repo_root, "add", "--", "config.py")
            self._run_git(repo_root, "commit", "-q", "-m", "resolve merge")
            local_commit = self._run_git(repo_root, "rev-parse", "HEAD")
            updates = (
                f"refs/heads/main {local_commit} "
                f"refs/heads/remote-side {remote_commit}\n"
            )

            issues = scan_git_push_updates(repo_root, updates)

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["commit"], local_commit)

    def test_scan_git_push_updates_handles_deletions_and_multiple_refs(self) -> None:
        """Deleted refs are skipped and duplicate update commits scan once."""
        with tempfile.TemporaryDirectory() as repo_root:
            self._initialize_history_repo(repo_root)
            pushed_commit = self._commit_file(
                repo_root, "config.py", f'aws_key = "{DUMMY_AWS}"\n'.encode()
            )
            updates = (
                f"refs/heads/deleted {'0' * 40} "
                f"refs/heads/deleted {pushed_commit}\n"
                f"refs/heads/first {pushed_commit} "
                f"refs/heads/first {'0' * 40}\n"
                f"refs/heads/second {pushed_commit} "
                f"refs/heads/second {'0' * 40}\n"
            )

            issues = scan_git_push_updates(repo_root, updates)

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["commit"], pushed_commit)

    def test_scan_git_push_updates_rejects_malformed_input(self) -> None:
        """Malformed pre-push input must fail explicitly."""
        with tempfile.TemporaryDirectory() as repo_root:
            self._initialize_history_repo(repo_root)
            with self.assertRaisesRegex(RuntimeError, "Invalid pre-push update data"):
                scan_git_push_updates(repo_root, "not a valid update\n")

    def test_scan_git_push_updates_detects_secret_removed_before_push(self) -> None:
        """A finding in an intermediate pushed commit remains detectable."""
        with tempfile.TemporaryDirectory() as repo_root:
            self._initialize_history_repo(repo_root)
            remote_commit = self._commit_file(repo_root, "README.txt", b"clean\n")
            secret_commit = self._commit_file(
                repo_root, "config.py", f'aws_key = "{DUMMY_AWS}"\n'.encode()
            )
            clean_commit = self._commit_file(
                repo_root, "config.py", b'aws_key = "removed"\n'
            )
            updates = (
                f"refs/heads/main {clean_commit} "
                f"refs/heads/main {remote_commit}\n"
            )

            issues = scan_git_push_updates(repo_root, updates)

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["commit"], secret_commit)

    def test_scan_git_commit_range_detects_secret_removed_before_head(self) -> None:
        """Range scanning finds a secret even when a later commit removes it."""
        with tempfile.TemporaryDirectory() as repo_root:
            self._initialize_history_repo(repo_root)
            self._commit_file(repo_root, "README.txt", b"base\n")
            base_commit = self._run_git(repo_root, "rev-parse", "HEAD")
            secret_commit = self._commit_file(
                repo_root, "settings.py", f'api_key = "{DUMMY_AWS}"\n'.encode()
            )
            head_commit = self._commit_file(
                repo_root, "settings.py", b"api_key = 'removed'\n"
            )

            issues = scan_git_commit_range(repo_root, base_commit, head_commit)

        self.assertEqual({issue["source"] for issue in issues}, {"settings.py"})
        self.assertEqual({issue["commit"] for issue in issues}, {secret_commit})
        self.assertIn(
            "AWS Access Key ID", {issue["matcher"] for issue in issues}
        )

    def test_scan_git_commit_range_ignores_findings_already_in_base(self) -> None:
        """Existing findings are not re-reported when a file changes in range."""
        with tempfile.TemporaryDirectory() as repo_root:
            self._initialize_history_repo(repo_root)
            base_commit = self._commit_file(
                repo_root,
                "settings.py",
                f'api_key = "{DUMMY_AWS}"\nvalue = 1\n'.encode(),
            )
            head_commit = self._commit_file(
                repo_root,
                "settings.py",
                f'api_key = "{DUMMY_AWS}"\nvalue = 2\n'.encode(),
            )

            issues = scan_git_commit_range(repo_root, base_commit, head_commit)

        self.assertEqual(issues, [])

    def test_scan_git_commit_range_rejects_non_ancestor_base(self) -> None:
        """The base must be an ancestor so the requested range is unambiguous."""
        with tempfile.TemporaryDirectory() as repo_root:
            self._initialize_history_repo(repo_root)
            self._commit_file(repo_root, "README.txt", b"main\n")
            main_commit = self._run_git(repo_root, "rev-parse", "HEAD")
            self._run_git(repo_root, "checkout", "-q", "-b", "other")
            head_commit = self._commit_file(repo_root, "README.txt", b"other\n")

            with self.assertRaisesRegex(ValueError, "base commit must be an ancestor"):
                scan_git_commit_range(repo_root, head_commit, main_commit)

    def test_scan_git_diff_reports_only_added_secret_lines(self) -> None:
        """Existing findings are omitted when their lines are unchanged."""
        with tempfile.TemporaryDirectory() as repo_root:
            self._initialize_history_repo(repo_root)
            path = os.path.join(repo_root, "config with spaces.py")
            original = f'old_key = "{DUMMY_AWS}"\n'
            relative_path = "config with spaces.py"
            base_commit = self._commit_file(repo_root, relative_path, original.encode())
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(
                    original
                    + f'new_key = "{DUMMY_AWS}"\n'
                    + 'internal_token = "corp_' + "c" * 20 + '"\n'
                )

            custom_rule = CustomRule(
                name="Company API Token",
                pattern=re.compile(r"\bcorp_[A-Za-z0-9]{20}\b"),
                severity=SeverityLevel.HIGH,
            )
            issues = scan_git_diff(
                base_commit,
                repo_root,
                custom_rules=[custom_rule],
            )

        self.assertEqual([issue["line"] for issue in issues], [2, 3])
        self.assertEqual(
            [issue["matcher"] for issue in issues],
            ["AWS Access Key ID", "Company API Token"],
        )

    def test_scan_git_diff_ignores_removed_secret_lines(self) -> None:
        """Deleting an old finding should not report it as a new finding."""
        with tempfile.TemporaryDirectory() as repo_root:
            self._initialize_history_repo(repo_root)
            path = os.path.join(repo_root, "config.py")
            original = f'old_key = "{DUMMY_AWS}"\n'
            base_commit = self._commit_file(repo_root, "config.py", original.encode())
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("old_key = None\n")

            issues = scan_git_diff(base_commit, repo_root)

        self.assertEqual(issues, [])

    def test_scan_git_diff_rejects_unknown_base(self) -> None:
        with tempfile.TemporaryDirectory() as repo_root:
            self._initialize_history_repo(repo_root)
            with self.assertRaisesRegex(ValueError, "Unable to resolve diff base"):
                scan_git_diff("missing-base", repo_root)

    def test_scan_text_detects_aws_key(self) -> None:
        """Identify AWS access key IDs accurately."""
        content = f'aws_key = "{DUMMY_AWS}"\n'
        issues = scan_text(content, "config.py")
        issue = next(
            issue for issue in issues if issue["matcher"] == "AWS Access Key ID"
        )
        self.assertEqual(issue["severity"], "MEDIUM")

    def test_scan_text_detects_aws_secret_access_key(self) -> None:
        """Detect AWS secret access keys separately from access key IDs."""
        content = f'aws_secret_access_key = "{DUMMY_AWS_SECRET}"\n'
        issues = scan_text(content, "config.py")
        issue = next(
            issue for issue in issues if issue["matcher"] == "AWS Secret Access Key"
        )
        self.assertEqual(issue["severity"], "CRITICAL")

    def test_scan_text_rejects_malformed_aws_secret_access_key_length(self) -> None:
        """Do not match AWS secret access key values longer than their fixed format."""
        value = DUMMY_AWS_SECRET + "x"
        content = f'aws_secret_access_key = "{value}"\n'
        issues = scan_text(content, "config.py")
        self.assertFalse(
            any(issue["matcher"] == "AWS Secret Access Key" for issue in issues)
        )

    def test_scan_text_detects_configured_custom_rule(self) -> None:
        """Custom patterns report their configured name and severity."""
        rule = CustomRule(
            name="Company API Token",
            pattern=re.compile(r"\bcorp_[A-Za-z0-9]{20}\b"),
            severity=SeverityLevel.CRITICAL,
        )
        value = "corp_" + "a" * 20

        issues = scan_text(f'token = "{value}"', "settings.py", [rule])

        match = next(issue for issue in issues if issue["matcher"] == rule.name)
        self.assertEqual(match["value"], value)
        self.assertEqual(match["severity"], "CRITICAL")
        self.assertEqual(match["reason"], "custom-pattern")
        self.assertEqual(match["confidence"], "medium")

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

    def test_scan_text_ignore_with_reason_and_future_expiry(self) -> None:
        """A documented, unexpired suppression should hide the finding."""
        expiry = (date.today() + timedelta(days=1)).isoformat()
        content = (
            f'aws_key = "{DUMMY_AWS}"  # secret-sentinel: ignore '
            f"reason: synthetic test fixture; expires: {expiry}\n"
        )
        self.assertEqual(scan_text(content, "test.py"), [])

    def test_scan_text_expired_ignore_does_not_suppress(self) -> None:
        """An expired suppression should leave the finding visible."""
        content = (
            f'aws_key = "{DUMMY_AWS}"  # secret-sentinel: ignore '
            "reason: obsolete fixture; expires: 2000-01-01\n"
        )
        issues = scan_text(content, "test.py")
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["line"], 1)

    def test_scan_text_invalid_expiry_does_not_suppress(self) -> None:
        """A malformed expiry must not silently suppress a finding."""
        content = (
            f'aws_key = "{DUMMY_AWS}"  # secret-sentinel: ignore '
            "reason: test fixture; expires: not-a-date\n"
        )
        self.assertEqual(len(scan_text(content, "test.py")), 1)

    def test_scan_text_disable_next_line_with_expiry(self) -> None:
        """An active next-line suppression hides only the following line."""
        expiry = (date.today() + timedelta(days=1)).isoformat()
        content = (
            f"# secret-sentinel: disable-next-line reason: test fixture; expires: {expiry}\n"
            f'aws_key1 = "{DUMMY_AWS}"\n'
            f'aws_key2 = "{DUMMY_AWS}"\n'
        )
        issues = scan_text(content, "test.py")
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["line"], 3)

    def test_scan_text_expired_disable_next_line_does_not_suppress(self) -> None:
        """An expired next-line suppression must not hide the following finding."""
        content = (
            "# secret-sentinel: disable-next-line reason: test fixture; expires: 2000-01-01\n"
            f'aws_key = "{DUMMY_AWS}"\n'
        )
        issues = scan_text(content, "test.py")
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["line"], 2)

    def test_audit_suppressions_text_reports_documented_active_directives(self) -> None:
        """A used suppression with a reason and future expiry is healthy."""
        content = (
            f'aws_key = "{DUMMY_AWS}"  # secret-sentinel: ignore '
            "reason: synthetic test fixture; expires: 2999-12-31\n"
            "# secret-sentinel: disable-next-line reason: fixture; expires: 2999-12-31\n"
            f'aws_key = "{DUMMY_AWS}"\n'
        )

        suppressions = audit_suppressions_text(content, "test.py")

        self.assertEqual(
            [item["statuses"] for item in suppressions],
            [["active"], ["active"]],
        )
        self.assertEqual([item["target_line"] for item in suppressions], [1, 3])
        self.assertNotIn(DUMMY_AWS, repr(suppressions))

    def test_audit_suppressions_text_reports_metadata_and_usage_problems(self) -> None:
        """Missing, invalid, expired, and unused suppressions are actionable."""
        content = (
            "# secret-sentinel: ignore\n"
            "# secret-sentinel: ignore reason: obsolete; expires: 2000-01-01\n"
            "# secret-sentinel: ignore reason: malformed; expires: not-a-date\n"
            "# secret-sentinel: disable-next-line\n"
        )

        suppressions = audit_suppressions_text(content, "test.py")

        self.assertEqual(
            [item["statuses"] for item in suppressions],
            [
                ["missing-reason", "missing-expiry", "unused"],
                ["expired"],
                ["invalid-expiry"],
                ["missing-reason", "missing-expiry", "unused"],
            ],
        )
        self.assertIsNone(suppressions[-1]["target_line"])

    def test_audit_suppressions_in_repo_honors_ignores(self) -> None:
        """Repository audits skip ignored paths and report relative locations."""
        with tempfile.TemporaryDirectory() as repo_root:
            included = os.path.join(repo_root, "src", "module.py")
            ignored = os.path.join(repo_root, "ignored", "module.py")
            os.makedirs(os.path.dirname(included))
            os.makedirs(os.path.dirname(ignored))
            with open(included, "w", encoding="utf-8") as handle:
                handle.write("# secret-sentinel: ignore\n")
            with open(ignored, "w", encoding="utf-8") as handle:
                handle.write("# secret-sentinel: ignore\n")

            suppressions = audit_suppressions_in_repo(
                repo_root, ignore_globs=["ignored/*"]
            )

        self.assertEqual(len(suppressions), 1)
        self.assertEqual(suppressions[0]["source"], "src/module.py")

    def test_audit_suppressions_text_uses_custom_rules_for_matching(self) -> None:
        """A custom detector match makes a next-line suppression active."""
        custom_rule = CustomRule(
            "Fixture Token",
            re.compile(r"fixture_[A-Z0-9]{8}"),
            SeverityLevel.HIGH,
        )
        content = (
            "# secret-sentinel: disable-next-line reason: fixture; expires: 2999-12-31\n"
            'value = "fixture_A1B2C3D4"\n'
        )

        suppressions = audit_suppressions_text(
            content, "test.py", custom_rules=[custom_rule]
        )

        self.assertEqual(suppressions[0]["statuses"], ["active"])

    def test_scan_text_detects_generic_secret(self) -> None:
        """Detect generic secret assignments."""
        content = 'api_key: "abcdef1234567890_super_secret"\n'
        issues = scan_text(content, "settings.yml")
        self.assertTrue(any(i["matcher"] == "Generic Secret Assignment" for i in issues))
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["confidence"], "medium")

    def test_scan_text_detects_encoded_provider_token(self) -> None:
        """Recognize known token formats after base64 decoding secret fields."""
        encoded_token = base64.b64encode(DUMMY_GITHUB.encode()).decode()
        issues = scan_text(f'token = "{encoded_token}"', "settings.py")

        encoded_findings = [
            issue for issue in issues if issue["reason"] == "encoded-pattern"
        ]
        self.assertEqual(len(issues), 1)
        self.assertEqual(len(encoded_findings), 1)
        self.assertEqual(encoded_findings[0]["matcher"], "GitHub Token")
        self.assertEqual(encoded_findings[0]["value"], encoded_token)
        self.assertNotIn(DUMMY_GITHUB, repr(issues))

    def test_scan_text_reports_complete_private_key_block(self) -> None:
        """A complete key block is one finding located on its header."""
        content = (
            "before = True\n"
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "synthetic-private-key-material\n"
            "-----END RSA PRIVATE KEY-----\n"
        )

        issues = scan_text(content, "key.pem")

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["matcher"], "Private Key")
        self.assertEqual(issues[0]["line"], 2)
        self.assertEqual(issues[0]["reason"], "private-key-block")
        self.assertEqual(issues[0]["confidence"], "high")
        self.assertIn("synthetic-private-key-material", issues[0]["value"])

    def test_private_key_header_alone_has_low_confidence(self) -> None:
        """A key header without its body is a weaker signal than a full block."""
        issues = scan_text("-----BEGIN RSA PRIVATE KEY-----", "key.pem")

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["confidence"], "low")
        self.assertEqual(issues[0]["reason"], "private-key-header")

    def test_private_key_block_respects_header_suppression(self) -> None:
        """A suppression on the key header also suppresses its multiline finding."""
        content = (
            "# secret-sentinel: disable-next-line reason: fixture; expires: 2999-12-31\n"
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "synthetic-private-key-material\n"
            "-----END RSA PRIVATE KEY-----\n"
        )

        self.assertEqual(scan_text(content, "key.pem"), [])

    def test_scan_text_detects_high_entropy_string(self) -> None:
        """Detect high-entropy values assigned to secret-related fields."""
        value = "K9zXwQ7p.L2vM5yB8.tR4cE1aD3.fG6hJ0n"
        content = f'secret_token = "{value}"\n'
        issues = scan_text(content, "secure.py")
        self.assertEqual(
            [issue["matcher"] for issue in issues], ["High entropy string"]
        )

    def test_scan_text_ignores_entropy_unrelated_to_secret_assignment(self) -> None:
        """Ignore unrelated entropy even beside secret-related wording."""
        content = (
            'print("secret rotation complete", '
            '"K9zXwQ7pL2vM5yB8tR4cE1aD3fG6hJ0n")\n'
        )
        self.assertEqual(scan_text(content, "logging.py"), [])

    def test_scan_text_does_not_flag_stripe_publishable_key(self) -> None:
        """Stripe publishable keys are not secret credentials."""
        publishable_key = "pk_test_" + "123456789012345678901234"
        content = f'publishable_key = "{publishable_key}"\n'
        issues = scan_text(content, "frontend.js")
        self.assertFalse(any(issue["matcher"] == "Stripe API Key" for issue in issues))

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

    def test_sanitize_source_path_keeps_dot_prefix_names_relative(self) -> None:
        """In-repository names beginning with dots remain relative."""
        repo_root = "/home/user/project"
        source = os.path.join(repo_root, "..private", "config.py")

        self.assertEqual(
            _sanitize_source_path(source, repo_root),
            "..private/config.py",
        )

    def test_normalize_path(self) -> None:
        """Path separators should be converted to forward slashes."""
        self.assertEqual(_normalize_path("folder\\sub\\file.py"), "folder/sub/file.py")

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

    def test_scan_paths_honors_explicit_empty_ignore_list(self) -> None:
        """An empty ignore list disables built-in path exclusions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            target_dir = os.path.join(tmpdir, "node_modules")
            os.makedirs(target_dir)
            target_file = os.path.join(target_dir, "app.py")
            with open(target_file, "w", encoding="utf-8") as handle:
                handle.write(f'api_key = "{DUMMY_AWS}"\n')

            issues = scan_paths([tmpdir], ignore_globs=[])

        self.assertTrue(
            any(issue["source"].endswith("node_modules/app.py") for issue in issues)
        )

    def test_scan_paths_skips_symlinks_and_reports_coverage(self) -> None:
        """Disk scans do not read symlink targets inside or outside the scan root."""
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_root = os.path.join(tmpdir, "repo")
            os.mkdir(repo_root)
            target = os.path.join(tmpdir, "outside.py")
            with open(target, "w", encoding="utf-8") as handle:
                handle.write(f'api_key = "{DUMMY_AWS}"\n')
            os.symlink(target, os.path.join(repo_root, "file-link.py"))
            os.symlink(tmpdir, os.path.join(repo_root, "directory-link"))
            direct_link = os.path.join(tmpdir, "direct-link.py")
            os.symlink(target, direct_link)
            nested_link_target = os.path.join(
                repo_root,
                "directory-link",
                os.path.basename(target),
            )
            coverage = ScanCoverage()

            issues = scan_paths([repo_root], coverage=coverage)
            direct_link_issues = scan_paths([direct_link], coverage=coverage)
            nested_link_issues = scan_paths([nested_link_target], coverage=coverage)

        self.assertEqual(issues, [])
        self.assertEqual(direct_link_issues, [])
        self.assertEqual(nested_link_issues, [])
        self.assertEqual(coverage.ignored_paths, 4)

    def test_scan_paths_reports_unreadable_files_in_coverage(self) -> None:
        """Read failures are counted instead of treated as scanned clean files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            target = os.path.join(tmpdir, "unreadable.py")
            with open(target, "w", encoding="utf-8") as handle:
                handle.write("value = 1\n")
            coverage = ScanCoverage()
            with patch("builtins.open", side_effect=PermissionError):
                issues = scan_paths([target], coverage=coverage)

        self.assertEqual(issues, [])
        self.assertEqual(coverage.unreadable_paths, 1)

    def test_scan_paths_returns_findings_in_stable_path_order(self) -> None:
        """Directory traversal emits findings in lexicographic path order."""
        with tempfile.TemporaryDirectory() as tmpdir:
            for name in ("z-last.py", "a-first.py"):
                with open(os.path.join(tmpdir, name), "w", encoding="utf-8") as handle:
                    handle.write(f'api_key = "{DUMMY_AWS}"\n')

            issues = scan_paths([tmpdir])

        sources = [os.path.basename(issue["source"]) for issue in issues]
        self.assertEqual(sources, sorted(sources))
        self.assertEqual(set(sources), {"a-first.py", "z-last.py"})

    def test_scan_paths_reports_coverage_counts(self) -> None:
        """Coverage distinguishes scanned, ignored, binary, and missing paths."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "clean.py"), "w", encoding="utf-8") as handle:
                handle.write("value = 1\n")
            with open(os.path.join(tmpdir, "ignored.txt"), "w", encoding="utf-8") as handle:
                handle.write("ignored\n")
            with open(os.path.join(tmpdir, "binary.bin"), "wb") as handle:
                handle.write(b"\x00binary")

            coverage = ScanCoverage()
            scan_paths(
                [tmpdir, os.path.join(tmpdir, "missing.py")],
                ignore_globs=["*ignored.txt"],
                coverage=coverage,
            )

        self.assertEqual(
            coverage.as_dict(),
            {
                "scanned_files": 1,
                "ignored_paths": 1,
                "binary_files": 1,
                "unreadable_paths": 0,
                "missing_paths": 1,
                "oversized_files": 0,
            },
        )

    def test_scan_staged_files(self) -> None:
        """Scan staged files using mocked git output."""
        with patch("secret_sentinel.scanner.get_staged_paths", return_value=["app.py"]):
            with patch(
                "secret_sentinel.scanner.get_staged_content",
                return_value=f'api_key = "{DUMMY_AWS}"\n',
            ):
                issues = scan_staged_files()
                self.assertTrue(
                    any(i["matcher"] == "AWS Access Key ID" for i in issues)
                )
                self.assertEqual(issues[0]["source"], "app.py")

    def test_staged_paths_support_unusual_names_and_renames(self) -> None:
        """Staged scanning handles newlines, pathspec syntax, and renamed files."""
        with tempfile.TemporaryDirectory() as repo_root:
            self._initialize_history_repo(repo_root)
            self._commit_file(
                repo_root,
                "rename-source.py",
                f'api_key = "{DUMMY_AWS}"\n'.encode(),
            )
            self._run_git(repo_root, "mv", "rename-source.py", "rename-target.py")
            unusual_paths = ["line\nbreak.py", ":(exclude)literal.py"]
            for path in unusual_paths:
                full_path = os.path.join(repo_root, path)
                with open(full_path, "w", encoding="utf-8") as handle:
                    handle.write(f'api_key = "{DUMMY_AWS}"\n')
            self._run_git(
                repo_root,
                "--literal-pathspecs",
                "add",
                "--",
                *unusual_paths,
            )

            staged_paths = get_staged_paths(repo_root)
            issues = scan_staged_files(repo_root=repo_root)

        self.assertEqual(set(staged_paths), {"rename-target.py", *unusual_paths})
        self.assertEqual(
            {issue["source"] for issue in issues},
            {"rename-target.py", *unusual_paths},
        )

    def test_staged_git_failures_raise_instead_of_looking_clean(self) -> None:
        """Git failures cannot be mistaken for an empty staged scan."""
        failed = subprocess.CompletedProcess(
            args=["git", "diff"], returncode=128, stdout=b"", stderr=b""
        )
        with patch("secret_sentinel.scanner._run_git_command", return_value=failed):
            with self.assertRaisesRegex(RuntimeError, "Unable to read staged files"):
                get_staged_paths()

    def test_scan_staged_files_applies_custom_rules(self) -> None:
        rule = CustomRule(
            name="Company API Token",
            pattern=re.compile(r"\bcorp_[A-Za-z0-9]{20}\b"),
            severity=SeverityLevel.CRITICAL,
        )
        with patch("secret_sentinel.scanner.get_staged_paths", return_value=["app.py"]):
            with patch(
                "secret_sentinel.scanner.get_staged_content",
                return_value='token = "corp_' + "d" * 20 + '"\n',
            ):
                issues = scan_staged_files(custom_rules=[rule])

        custom_issue = next(issue for issue in issues if issue["matcher"] == rule.name)
        self.assertEqual(custom_issue["severity"], "CRITICAL")

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

            mock_git.return_value = MagicMock(
                returncode=0,
                stdout=b"file1.py\0file2.py\0",
            )
            self.assertEqual(get_staged_paths(), ["file1.py", "file2.py"])

            mock_git.return_value = MagicMock(returncode=1, stdout="")
            with self.assertRaisesRegex(RuntimeError, "Unable to read staged files"):
                get_staged_paths()

            mock_git.return_value = MagicMock(returncode=0, stdout=b"content")
            self.assertEqual(get_staged_content("file1.py"), "content")

            mock_git.return_value = MagicMock(returncode=1, stdout=b"")
            with self.assertRaisesRegex(RuntimeError, "Unable to read staged file"):
                get_staged_content("file1.py")


class TestRulePackThree(unittest.TestCase):
    """Rules and fixes added in rule pack 3."""

    BODY = "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"

    def matchers(self, content: str, source: str = "app.py") -> list:
        return [issue["matcher"] for issue in scan_text(content, source)]

    def test_scans_files_with_non_ascii_text(self) -> None:
        """UTF-8 files with accented text should still be scanned."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "config.py")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(f'# Café config\ntoken = "ghp_{self.BODY}"\n')
            issues = scan_paths([path], repo_root=tmpdir)
        self.assertEqual([i["matcher"] for i in issues], ["GitHub Token"])

    def test_detects_provider_tokens(self) -> None:
        """Newer GitHub formats and added providers should be detected."""
        cases = {
            f'a = "gho_{self.BODY}"': "GitHub Token",
            f'a = "github_pat_{"A" * 82}"': "GitHub Token",
            'a = "glpat-' + "AbCdEfGhIjKlMnOpQrSt" + '"': "GitLab Token",
            f'a = "SG.{"a" * 22}.{"b" * 43}"': "SendGrid API Key",
            f'a = "AccountName=x;AccountKey={"Q" * 86}==;"': "Azure Storage Account Key",
            f'a = "GOCSPX-{"c" * 28}"': "Google OAuth Client Secret",
            f'a = "shpat_{"0" * 32}"': "Shopify Access Token",
            f'a = "dop_v1_{"f" * 64}"': "DigitalOcean Token",
            f'a = "dapi{"e" * 32}"': "Databricks Token",
        }
        for content, matcher in cases.items():
            with self.subTest(matcher=matcher):
                self.assertIn(matcher, self.matchers(content))

    def test_detects_password_assignments(self) -> None:
        """Short and symbol-heavy password values should be detected."""
        for content in (
            'password = "Summer2024!"',
            "DB_PASSWORD=Xk9#mQ2!vL7@pR4$",
            'export API_SECRET="s3cr3t-Value!"',
        ):
            with self.subTest(content=content):
                self.assertEqual(self.matchers(content, ".env"), ["Password Assignment"])

    def test_ignores_password_placeholders(self) -> None:
        """Placeholders, references, and plain words should not be reported."""
        for content in (
            'password = "password"',
            'password = "${DB_PASSWORD}"',
            'password = "********"',
            'password: "Passwort eingeben"',
            "PASSWORD=$DB_PASS",
            'secret = "notsecret"',
            "SECRET_KEY_PATH=/run/secrets/key",
            'password = "%(db_pass)s"',
        ):
            with self.subTest(content=content):
                self.assertEqual(self.matchers(content), [])

    def test_default_ignores_nested_dependency_directories(self) -> None:
        """Nested node_modules and virtualenvs should be ignored by default."""
        from secret_sentinel.config import DEFAULT_IGNORE

        for path in ("/r/packages/a/node_modules/x.js", "/r/svc/.venv/lib/x.py"):
            with self.subTest(path=path):
                self.assertTrue(_is_ignored(path, DEFAULT_IGNORE, "/r"))
        self.assertFalse(_is_ignored("/r/src/env/settings.py", DEFAULT_IGNORE, "/r"))
        for path in ("/r/dist/app.min.js", "/r/dist/app.min.css", "/r/dist/app.js.map"):
            with self.subTest(path=path):
                self.assertTrue(_is_ignored(path, DEFAULT_IGNORE, "/r"))

    def test_skips_and_reports_oversized_files(self) -> None:
        """Files over the size limit should be skipped and counted."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "big.txt")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(f'token = "ghp_{self.BODY}"\n')
            coverage = ScanCoverage()
            with patch("secret_sentinel.scanner.MAX_FILE_BYTES", 10):
                with self.assertLogs("secret_sentinel", level="WARNING"):
                    issues = scan_paths([tmpdir], repo_root=tmpdir, coverage=coverage)
        self.assertEqual(issues, [])
        self.assertEqual(coverage.oversized_files, 1)
        self.assertEqual(coverage.scanned_files, 0)


if __name__ == "__main__":
    unittest.main()
