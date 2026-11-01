"""Tests for Secret Sentinel command-line interface."""

import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from secret_sentinel.cli import (
    build_parser,
    install_git_hook,
    main,
    parse_args,
    parse_args_from,
    scan_paths as cli_scan_paths,
    setup_logging,
    uninstall_git_hook,
)
from secret_sentinel.history import ScanHistory


DUMMY_AWS = "AKIA" + "1234567890ABCDEF"


class TestCLI(unittest.TestCase):
    """Test suite for CLI argument parsing and execution."""

    def test_build_parser(self) -> None:
        """Verify parser construction."""
        parser = build_parser()
        self.assertEqual(parser.prog, "secret-sentinel")

    def test_parse_args_defaults(self) -> None:
        """Default arguments should have empty paths and staged false."""
        args = parse_args([])
        self.assertEqual(args.paths, [])
        self.assertFalse(args.staged)
        self.assertFalse(args.no_ai)
        self.assertFalse(args.debug)

    def test_parse_args_for_staged_scan(self) -> None:
        """Test parsing --staged and --no-ai."""
        args = parse_args(["--staged", "--no-ai"])
        self.assertTrue(args.staged)
        self.assertTrue(args.no_ai)

    def test_parse_args_for_git_history_scan(self) -> None:
        """Parse the distinct Git history scan option."""
        args = parse_args(["--git-history"])
        self.assertTrue(args.git_history)
        self.assertFalse(args.all_refs)
        self.assertTrue(parse_args(["--git-history", "--all-refs"]).all_refs)
        self.assertEqual(parse_args(["--diff", "origin/main"]).diff, "origin/main")

    def test_parse_args_for_baseline_modes(self) -> None:
        """Parse baseline checking and initialization modes."""
        self.assertTrue(parse_args(["--baseline"]).baseline)
        self.assertTrue(parse_args(["--update-baseline"]).update_baseline)
        with self.assertRaises(SystemExit):
            parse_args(["--baseline", "--update-baseline"])

    def test_parse_args_for_file_paths(self) -> None:
        """Test positional path arguments."""
        args = parse_args(["src", "tests"])
        self.assertEqual(args.paths, ["src", "tests"])

    def test_parse_args_hook_flags(self) -> None:
        """Test hook installation and uninstallation flags."""
        args_install = parse_args(["--install-hook"])
        self.assertTrue(args_install.install_hook)
        self.assertFalse(args_install.uninstall_hook)

        args_uninstall = parse_args(["--uninstall-hook"])
        self.assertTrue(args_uninstall.uninstall_hook)

    def test_parse_args_history_and_stats(self) -> None:
        """Test history and statistics flags."""
        args = parse_args(["--history", "--history-limit", "25", "--stats", "--clear-history"])
        self.assertTrue(args.history)
        self.assertEqual(args.history_limit, 25)
        self.assertTrue(args.stats)
        self.assertTrue(args.clear_history)

    def test_parse_args_from_alias(self) -> None:
        """Ensure parse_args_from alias behaves identically."""
        args = parse_args_from(["--debug", "--staged"])
        self.assertTrue(args.debug)
        self.assertTrue(args.staged)

    def test_setup_logging(self) -> None:
        """Verify logger configuration under debug and non-debug modes."""
        setup_logging(debug=True)
        setup_logging(debug=False)

    def test_install_and_uninstall_git_hook(self) -> None:
        """Test creating and removing git pre-commit hook."""
        with tempfile.TemporaryDirectory() as tmpdir:
            hooks_dir = os.path.join(tmpdir, ".git", "hooks")
            os.makedirs(hooks_dir)

            install_git_hook(tmpdir)
            hook_file = os.path.join(hooks_dir, "pre-commit")
            self.assertTrue(os.path.exists(hook_file))

            with open(hook_file, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("secret_sentinel.cli", content)
            self.assertIn("secret-sentinel managed hook", content)

            uninstall_git_hook(tmpdir)
            self.assertFalse(os.path.exists(hook_file))

    def test_install_git_hook_error(self) -> None:
        """Installing hook without .git/hooks should exit with error code 1."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(SystemExit) as ctx:
                install_git_hook(tmpdir)
            self.assertEqual(ctx.exception.code, 1)

    def test_install_git_hook_preserves_existing_hook(self) -> None:
        """Installation must not replace a hook not managed by Secret Sentinel."""
        with tempfile.TemporaryDirectory() as tmpdir:
            hooks_dir = os.path.join(tmpdir, ".git", "hooks")
            os.makedirs(hooks_dir)
            hook_file = os.path.join(hooks_dir, "pre-commit")
            with open(hook_file, "w", encoding="utf-8") as handle:
                handle.write("#!/bin/sh\necho existing\n")

            with self.assertRaises(SystemExit) as ctx:
                install_git_hook(tmpdir)

            self.assertEqual(ctx.exception.code, 1)
            with open(hook_file, "r", encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "#!/bin/sh\necho existing\n")

    def test_uninstall_git_hook_preserves_unmanaged_hook(self) -> None:
        """Uninstallation must not remove a hook not managed by Secret Sentinel."""
        with tempfile.TemporaryDirectory() as tmpdir:
            hooks_dir = os.path.join(tmpdir, ".git", "hooks")
            os.makedirs(hooks_dir)
            hook_file = os.path.join(hooks_dir, "pre-commit")
            with open(hook_file, "w", encoding="utf-8") as handle:
                handle.write("#!/bin/sh\necho existing\n")

            with self.assertRaises(SystemExit) as ctx:
                uninstall_git_hook(tmpdir)

            self.assertEqual(ctx.exception.code, 1)
            self.assertTrue(os.path.isfile(hook_file))

    def test_uninstall_git_hook_not_found(self) -> None:
        """Uninstalling non-existent hook should complete without raising error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            uninstall_git_hook(tmpdir)

    def test_main_clean_scan(self) -> None:
        """Main should return 0 when no issues are found."""
        with patch("secret_sentinel.cli.scan_paths", return_value=[]):
            with patch("secret_sentinel.cli.get_git_root", return_value=None):
                exit_code = main(["--no-ai"])
                self.assertEqual(exit_code, 0)

    def test_main_issues_found(self) -> None:
        """Main should return 1 when secret issues are detected."""
        mock_issues = [
            {
                "source": "app.py",
                "line": 5,
                "matcher": "AWS Secret Access Key",
                "value": DUMMY_AWS,
                "snippet": f'key = "{DUMMY_AWS}"',
                "confidence": "high",
                "severity": "CRITICAL",
            }
        ]
        with patch("secret_sentinel.cli.scan_paths", return_value=mock_issues):
            with patch("secret_sentinel.cli.get_git_root", return_value=None):
                exit_code = main(["--no-ai"])
                self.assertEqual(exit_code, 1)

    def test_main_update_baseline_records_findings_without_failing(self) -> None:
        """Baseline initialization records current findings without blocking."""
        issue = {
            "source": "config.py",
            "line": 2,
            "matcher": "AWS Secret Access Key",
            "value": DUMMY_AWS,
            "snippet": f'key = "{DUMMY_AWS}"',
            "confidence": "high",
            "severity": "CRITICAL",
        }
        with tempfile.TemporaryDirectory() as repo_root:
            with patch.dict(
                os.environ, {"SECRET_SENTINEL_BASELINE_KEY": "test-key-" + "x" * 32}
            ):
                with patch("secret_sentinel.cli.get_git_root", return_value=repo_root):
                    with patch("secret_sentinel.cli.scan_paths", return_value=[issue]):
                        self.assertEqual(main(["--update-baseline", "--no-ai"]), 0)
            baseline_path = os.path.join(
                repo_root, ".secret-sentinel", "baseline.json"
            )
            with open(baseline_path, "r", encoding="utf-8") as handle:
                baseline_contents = handle.read()
        self.assertNotIn(DUMMY_AWS, baseline_contents)

    def test_main_baseline_filters_known_findings(self) -> None:
        """Baseline scan exits successfully when all findings are already known."""
        issue = {
            "source": "config.py",
            "line": 2,
            "matcher": "AWS Secret Access Key",
            "value": DUMMY_AWS,
            "snippet": f'key = "{DUMMY_AWS}"',
            "confidence": "high",
            "severity": "CRITICAL",
        }
        with tempfile.TemporaryDirectory() as repo_root:
            with patch.dict(
                os.environ, {"SECRET_SENTINEL_BASELINE_KEY": "test-key-" + "x" * 32}
            ):
                with patch("secret_sentinel.cli.get_git_root", return_value=repo_root):
                    with patch("secret_sentinel.cli.scan_paths", return_value=[issue]):
                        self.assertEqual(main(["--update-baseline", "--no-ai"]), 0)
                        self.assertEqual(main(["--baseline", "--no-ai"]), 0)

    def test_main_baseline_reports_new_findings(self) -> None:
        """A finding absent from the baseline still blocks the scan."""
        original = {
            "source": "config.py",
            "line": 2,
            "matcher": "AWS Secret Access Key",
            "value": DUMMY_AWS,
            "snippet": f'key = "{DUMMY_AWS}"',
            "confidence": "high",
            "severity": "CRITICAL",
        }
        new_issue = dict(original, value="AKIA" + "FEDCBA0987654321")
        with tempfile.TemporaryDirectory() as repo_root:
            with patch.dict(
                os.environ, {"SECRET_SENTINEL_BASELINE_KEY": "test-key-" + "x" * 32}
            ):
                with patch("secret_sentinel.cli.get_git_root", return_value=repo_root):
                    with patch("secret_sentinel.cli.scan_paths", return_value=[original]):
                        self.assertEqual(main(["--update-baseline", "--no-ai"]), 0)
                    with patch(
                        "secret_sentinel.cli.scan_paths",
                        return_value=[original, new_issue],
                    ):
                        self.assertEqual(main(["--baseline", "--no-ai"]), 1)

    def test_main_baseline_requires_existing_file(self) -> None:
        """Baseline checks fail with an actionable message when no baseline exists."""
        with tempfile.TemporaryDirectory() as repo_root:
            with patch.dict(
                os.environ, {"SECRET_SENTINEL_BASELINE_KEY": "test-key-" + "x" * 32}
            ):
                with patch("secret_sentinel.cli.get_git_root", return_value=repo_root):
                    self.assertEqual(main(["--baseline", "--no-ai"]), 1)

    def test_main_baseline_requires_key(self) -> None:
        """Baseline operations fail clearly when the key is not configured."""
        with tempfile.TemporaryDirectory() as repo_root:
            with patch.dict(os.environ, {"SECRET_SENTINEL_BASELINE_KEY": ""}):
                with patch("secret_sentinel.cli.get_git_root", return_value=repo_root):
                    self.assertEqual(main(["--baseline", "--no-ai"]), 1)

    def test_main_baseline_rejects_non_scan_options(self) -> None:
        """Baseline modes should not be silently ignored by other CLI commands."""
        self.assertEqual(main(["--baseline", "--history"]), 2)

    def test_main_git_history_scan_uses_threshold_and_records_history(self) -> None:
        """Git history mode should scan, format, and record its own scan type."""
        issue = {
            "source": "config.py",
            "line": 2,
            "matcher": "AWS Secret Access Key",
            "value": DUMMY_AWS,
            "snippet": f'key = "{DUMMY_AWS}"',
            "confidence": "high",
            "severity": "CRITICAL",
            "commit": "0123456789abcdef",
        }
        with tempfile.TemporaryDirectory() as repo_root:
            history = ScanHistory(repo_root)
            with patch("secret_sentinel.cli.get_git_root", return_value=repo_root):
                with patch("secret_sentinel.cli.scan_git_history", return_value=[issue]) as scan:
                    self.assertEqual(main(["--git-history", "--format", "json"]), 1)
                    scan.assert_called_once()
            records = history.get_history()

        self.assertEqual(records[0]["scan_type"], "git-history")
        self.assertEqual(records[0]["status"], "blocked")

    def test_main_all_refs_requires_git_history(self) -> None:
        """All-refs mode is only valid for a Git history scan."""
        with patch("secret_sentinel.cli.get_git_root", return_value=None):
            self.assertEqual(main(["--all-refs"]), 2)

    def test_main_git_history_forwards_all_refs_option(self) -> None:
        """The CLI should pass all-refs mode to the history scanner."""
        with tempfile.TemporaryDirectory() as repo_root:
            with patch("secret_sentinel.cli.get_git_root", return_value=repo_root):
                with patch("secret_sentinel.cli.scan_git_history", return_value=[]) as scan:
                    self.assertEqual(
                        main(["--git-history", "--all-refs", "--no-ai"]),
                        0,
                    )
            self.assertTrue(scan.call_args.kwargs["all_refs"])

    def test_main_git_history_scan_rejects_paths_and_staged(self) -> None:
        """History mode should not ambiguously accept current-tree scan options."""
        with patch("secret_sentinel.cli.get_git_root", return_value=None):
            self.assertEqual(main(["--git-history", "src/"]), 2)
            self.assertEqual(main(["--git-history", "--staged"]), 2)

    def test_main_diff_rejects_paths_and_staged(self) -> None:
        with patch("secret_sentinel.cli.get_git_root", return_value=None):
            self.assertEqual(main(["--diff", "HEAD~1", "src/"]), 2)
            self.assertEqual(main(["--diff", "HEAD~1", "--staged"]), 2)

    def test_main_diff_forwards_base_and_custom_rules(self) -> None:
        with tempfile.TemporaryDirectory() as repo_root:
            with patch("secret_sentinel.cli.get_git_root", return_value=repo_root):
                with patch("secret_sentinel.cli.scan_paths", return_value=[]) as scan:
                    self.assertEqual(main(["--diff", "HEAD~1", "--no-ai"]), 0)
            self.assertEqual(scan.call_args.kwargs["diff_base"], "HEAD~1")

    def test_main_git_history_scan_reports_errors(self) -> None:
        """History scan errors should fail explicitly with a generic message."""
        with tempfile.TemporaryDirectory() as repo_root:
            with patch("secret_sentinel.cli.get_git_root", return_value=repo_root):
                with patch(
                    "secret_sentinel.cli.scan_git_history",
                    side_effect=RuntimeError("internal detail"),
                ):
                    self.assertEqual(main(["--git-history"]), 1)

    def test_main_history_and_stats_with_data(self) -> None:
        """Test history and statistics CLI commands when records exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            history = ScanHistory(tmpdir)
            history.record_scan(
                [{"matcher": "AWS Secret Access Key", "source": "a.py", "line": 1}],
                scan_type="manual",
                status="blocked",
            )
            with patch("secret_sentinel.cli.get_git_root", return_value=tmpdir):
                self.assertEqual(main(["--history"]), 0)
                self.assertEqual(main(["--stats"]), 0)

    def test_main_install_and_uninstall_flags(self) -> None:
        """Test invoking install and uninstall through main."""
        with tempfile.TemporaryDirectory() as tmpdir:
            hooks_dir = os.path.join(tmpdir, ".git", "hooks")
            os.makedirs(hooks_dir)
            with patch("secret_sentinel.cli.get_git_root", return_value=tmpdir):
                self.assertEqual(main(["--install-hook"]), 0)
                self.assertEqual(main(["--uninstall-hook"]), 0)

    def test_cli_scan_paths_execution(self) -> None:
        """Test cli.scan_paths with debug and no-ai flags."""
        with tempfile.TemporaryDirectory() as tmpdir:
            clean_file = os.path.join(tmpdir, "clean.py")
            with open(clean_file, "w", encoding="utf-8") as f:
                f.write("a = 1\n")

            secret_file = os.path.join(tmpdir, "secret.py")
            with open(secret_file, "w", encoding="utf-8") as f:
                f.write(f'key = "{DUMMY_AWS}"\n')

            issues = cli_scan_paths([clean_file, secret_file], no_ai=True, staged=False, debug=True)
            self.assertTrue(any(i["matcher"] == "AWS Secret Access Key" for i in issues))

    def test_cli_scan_uses_custom_rule_severity(self) -> None:
        """Configured custom rules should participate in severity blocking."""
        with tempfile.TemporaryDirectory() as repo_root:
            config_path = os.path.join(repo_root, ".secret-sentinel.ini")
            with open(config_path, "w", encoding="utf-8") as handle:
                handle.write(
                    "[custom_rules]\n"
                    "Company API Token = CRITICAL | \\bcorp_[A-Za-z0-9]{20}\\b\n"
                )
            token = "corp_" + "a" * 20
            source_path = os.path.join(repo_root, "settings.py")
            with open(source_path, "w", encoding="utf-8") as handle:
                handle.write(f'api_token = "{token}"\n')

            with patch("secret_sentinel.cli.get_git_root", return_value=repo_root):
                self.assertEqual(
                    main(["--no-ai", "--fail-on", "HIGH", source_path]),
                    1,
                )

    def test_cli_reports_invalid_custom_rule_config(self) -> None:
        """Invalid detector configuration should fail with a CLI error."""
        with tempfile.TemporaryDirectory() as repo_root:
            config_path = os.path.join(repo_root, ".secret-sentinel.ini")
            with open(config_path, "w", encoding="utf-8") as handle:
                handle.write("[custom_rules]\nBroken = HIGH | [\n")
            with patch("secret_sentinel.cli.get_git_root", return_value=repo_root):
                self.assertEqual(main(["--no-ai"]), 2)

    def test_cli_scan_paths_with_ai_enabled(self) -> None:
        """Test cli.scan_paths when AI validation is invoked on disk issues."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = os.path.join(tmpdir, ".secret-sentinel.ini")
            with open(config_path, "w", encoding="utf-8") as handle:
                handle.write(
                    "[secret-sentinel]\n"
                    "ai_enabled = true\n"
                    "ai_cloud_enabled = true\n"
                )
            secret_file = os.path.join(tmpdir, "secret.py")
            with open(secret_file, "w", encoding="utf-8") as f:
                f.write(f'key = "{DUMMY_AWS}"\n')

            with patch("secret_sentinel.cli.get_git_root", return_value=tmpdir):
                with patch(
                    "secret_sentinel.cli.validate_issues",
                    return_value=[],
                ) as validate:
                    issues = cli_scan_paths([secret_file], no_ai=False, staged=False, debug=False)
                    self.assertEqual(issues, [])
                    self.assertTrue(validate.call_args.kwargs["allow_cloud"])

    def test_main_format_json(self) -> None:
        """Main with --format json should return exit code 0 when clean."""
        with patch("secret_sentinel.cli.scan_paths", return_value=[]):
            with patch("secret_sentinel.cli.get_git_root", return_value=None):
                self.assertEqual(main(["--format", "json", "--no-ai"]), 0)

    def test_main_format_sarif(self) -> None:
        """Main with --format sarif should return exit code 0 when clean."""
        with patch("secret_sentinel.cli.scan_paths", return_value=[]):
            with patch("secret_sentinel.cli.get_git_root", return_value=None):
                self.assertEqual(main(["--format", "sarif", "--no-ai"]), 0)

    def test_main_output_to_file(self) -> None:
        """Main with --output should write report to target file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = os.path.join(tmpdir, "report.json")
            with patch("secret_sentinel.cli.scan_paths", return_value=[]):
                with patch("secret_sentinel.cli.get_git_root", return_value=None):
                    self.assertEqual(main(["--format", "json", "--output", output_file]), 0)
            self.assertTrue(os.path.exists(output_file))

    def test_main_fail_on_threshold_allows(self) -> None:
        """Issues below the fail-on threshold should not block commit (exit code 0)."""
        mock_medium_issue = [
            {
                "source": "app.py",
                "line": 5,
                "matcher": "High entropy string",
                "value": "randomEntropyString123456",
                "snippet": 'entropy = "randomEntropyString123456"',
                "confidence": "medium",
                "severity": "MEDIUM",
            }
        ]
        with patch("secret_sentinel.cli.scan_paths", return_value=mock_medium_issue):
            with patch("secret_sentinel.cli.get_git_root", return_value=None):
                self.assertEqual(main(["--fail-on", "HIGH", "--no-ai"]), 0)

    def test_main_fail_on_threshold_blocks(self) -> None:
        """Issues meeting or exceeding fail-on threshold should block commit (exit code 1)."""
        mock_critical_issue = [
            {
                "source": "app.py",
                "line": 5,
                "matcher": "AWS Secret Access Key",
                "value": DUMMY_AWS,
                "snippet": f'key = "{DUMMY_AWS}"',
                "confidence": "high",
                "severity": "CRITICAL",
            }
        ]
        with patch("secret_sentinel.cli.scan_paths", return_value=mock_critical_issue):
            with patch("secret_sentinel.cli.get_git_root", return_value=None):
                self.assertEqual(main(["--fail-on", "HIGH", "--no-ai"]), 1)


if __name__ == "__main__":
    unittest.main()
