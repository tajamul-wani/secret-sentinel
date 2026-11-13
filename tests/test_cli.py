"""Tests for Secret Sentinel command-line interface."""

import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch

from secret_sentinel.baseline import ScanBaseline
from secret_sentinel.cli import (
    build_parser,
    install_git_hook,
    install_git_pre_push_hook,
    main,
    parse_args,
    parse_args_from,
    setup_logging,
    uninstall_git_hook,
    uninstall_git_pre_push_hook,
)
from secret_sentinel.cli import (
    scan_paths as cli_scan_paths,
)
from secret_sentinel.history import ScanHistory
from secret_sentinel.scanner import ScanCoverage

DUMMY_AWS = "AKIA" + "1234567890ABCDEF"


class TestCLI(unittest.TestCase):
    """Test suite for CLI argument parsing and execution."""

    def test_build_parser(self) -> None:
        """Verify parser construction."""
        parser = build_parser()
        self.assertEqual(parser.prog, "secret-sentinel")
        self.assertIn("--setup", parser.format_help())
        self.assertIn("secret-sentinel --staged", parser.format_help())

    def test_parse_args_setup(self) -> None:
        """Parse the interactive setup guide option."""
        self.assertTrue(parse_args(["--setup"]).setup)

    def test_parse_args_audit_suppressions(self) -> None:
        """Parse the read-only suppression audit command."""
        self.assertTrue(parse_args(["--audit-suppressions"]).audit_suppressions)

    def test_parse_args_defaults(self) -> None:
        """Default arguments should have empty paths and staged false."""
        args = parse_args([])
        self.assertEqual(args.paths, [])
        self.assertFalse(args.staged)
        self.assertFalse(args.no_ai)
        self.assertFalse(args.debug)
        self.assertFalse(args.coverage)

    def test_parse_args_for_coverage(self) -> None:
        """Parse the optional explicit-path coverage report switch."""
        self.assertTrue(parse_args([".", "--coverage"]).coverage)

    def test_parse_args_for_strict_coverage(self) -> None:
        """Parse the explicit-path strict coverage switch."""
        self.assertTrue(parse_args([".", "--strict-coverage"]).strict_coverage)

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

    def test_parse_args_pre_push_hook_options(self) -> None:
        """Parse pre-push hook management and hidden hook execution options."""
        self.assertTrue(parse_args(["--install-pre-push-hook"]).install_pre_push_hook)
        self.assertTrue(
            parse_args(["--uninstall-pre-push-hook"]).uninstall_pre_push_hook
        )
        self.assertTrue(parse_args(["--pre-push"]).pre_push)

    def test_parse_args_history_and_stats(self) -> None:
        """Test history and statistics flags."""
        args = parse_args(["--history", "--history-limit", "25", "--stats", "--clear-history"])
        self.assertTrue(args.history)
        self.assertEqual(args.history_limit, 25)
        self.assertTrue(args.stats)
        self.assertTrue(args.clear_history)

    def test_parse_args_for_commit_range_scan(self) -> None:
        """Parse explicit base and head revisions for range scans."""
        args = parse_args(["--commit-range", "origin/main", "HEAD"])
        self.assertEqual(args.commit_range, ["origin/main", "HEAD"])

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
            self.assertIn("repo_root = Path.cwd().resolve()", content)

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

    def test_install_and_uninstall_git_pre_push_hook(self) -> None:
        """Install and remove the managed pre-push hook safely."""
        with tempfile.TemporaryDirectory() as repo_root:
            hooks_dir = os.path.join(repo_root, ".git", "hooks")
            os.makedirs(hooks_dir)

            install_git_pre_push_hook(repo_root)

            hook_path = os.path.join(hooks_dir, "pre-push")
            self.assertTrue(os.path.isfile(hook_path))
            self.assertTrue(os.access(hook_path, os.X_OK))
            content = Path(hook_path).read_text(encoding="utf-8")
            self.assertIn("secret-sentinel managed pre-push hook", content)
            self.assertIn('main(["--pre-push"])', content)

            uninstall_git_pre_push_hook(repo_root)
            self.assertFalse(os.path.exists(hook_path))

    def test_pre_push_hook_management_preserves_unmanaged_hook(self) -> None:
        """Pre-push installation and removal must preserve unmanaged hooks."""
        with tempfile.TemporaryDirectory() as repo_root:
            hooks_dir = os.path.join(repo_root, ".git", "hooks")
            os.makedirs(hooks_dir)
            hook_path = os.path.join(hooks_dir, "pre-push")
            original = "#!/bin/sh\necho existing\n"
            Path(hook_path).write_text(original, encoding="utf-8")

            with self.assertRaises(SystemExit) as install_error:
                install_git_pre_push_hook(repo_root)
            self.assertEqual(install_error.exception.code, 1)

            with self.assertRaises(SystemExit) as uninstall_error:
                uninstall_git_pre_push_hook(repo_root)
            self.assertEqual(uninstall_error.exception.code, 1)
            self.assertEqual(Path(hook_path).read_text(encoding="utf-8"), original)

    def test_pre_push_hook_blocks_new_findings_and_allows_clean_pushes(self) -> None:
        """The installed hook allows clean pushes and blocks newly added secrets."""
        with tempfile.TemporaryDirectory() as temp_root:
            local_repo = os.path.join(temp_root, "local")
            remote_repo = os.path.join(temp_root, "remote.git")
            os.makedirs(local_repo)
            project_root = str(Path(__file__).resolve().parents[1])
            environment = os.environ.copy()
            existing_pythonpath = environment.get("PYTHONPATH", "")
            environment["PYTHONPATH"] = os.pathsep.join(
                path for path in (project_root, existing_pythonpath) if path
            )

            def run_git(
                directory: str,
                *arguments: str,
                check: bool = True,
            ) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    ["git", *arguments],
                    cwd=directory,
                    env=environment,
                    capture_output=True,
                    text=True,
                    check=check,
                )

            run_git(temp_root, "init", "--bare", "-q", remote_repo)
            run_git(local_repo, "init", "-q")
            run_git(local_repo, "config", "user.name", "Test User")
            run_git(local_repo, "config", "user.email", "test@example.invalid")
            Path(local_repo, "README.txt").write_text("clean\n", encoding="utf-8")
            run_git(local_repo, "add", "README.txt")
            run_git(local_repo, "commit", "-q", "-m", "clean commit")
            run_git(local_repo, "remote", "add", "origin", remote_repo)
            install_git_pre_push_hook(local_repo)

            clean_push = run_git(
                local_repo,
                "push",
                "origin",
                "HEAD:refs/heads/main",
                check=False,
            )
            self.assertEqual(
                clean_push.returncode, 0, clean_push.stdout + clean_push.stderr
            )
            previous_remote_commit = run_git(
                local_repo, "ls-remote", "origin", "refs/heads/main"
            ).stdout.split()[0]

            Path(local_repo, "settings.py").write_text(
                f'aws_key = "{DUMMY_AWS}"\n', encoding="utf-8"
            )
            run_git(local_repo, "add", "settings.py")
            run_git(local_repo, "commit", "-q", "-m", "add test finding")
            blocked_push = run_git(
                local_repo,
                "push",
                "origin",
                "HEAD:refs/heads/main",
                check=False,
            )

            self.assertNotEqual(blocked_push.returncode, 0)
            push_output = blocked_push.stdout + blocked_push.stderr
            self.assertIn("[REDACTED]", push_output)
            self.assertNotIn(DUMMY_AWS, push_output)
            self.assertEqual(
                run_git(local_repo, "ls-remote", "origin", "refs/heads/main")
                .stdout.split()[0],
                previous_remote_commit,
            )
            history = ScanHistory(local_repo).get_history(limit=2)
            self.assertEqual(
                [record["scan_type"] for record in history],
                ["pre-push", "pre-push"],
            )
            self.assertEqual(
                [record["status"] for record in history], ["blocked", "completed"]
            )

    def test_main_clean_scan(self) -> None:
        """Main should return 0 when no issues are found."""
        with (
            patch("secret_sentinel.cli.scan_paths", return_value=[]),
            patch("secret_sentinel.cli.get_git_root", return_value=None),
        ):
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
        with (
            patch("secret_sentinel.cli.scan_paths", return_value=mock_issues),
            patch("secret_sentinel.cli.get_git_root", return_value=None),
        ):
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
            with (
                patch.dict(
        os.environ, {"SECRET_SENTINEL_BASELINE_KEY": "test-key-" + "x" * 32}
    ), patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
                patch("secret_sentinel.cli.scan_paths", return_value=[issue]),
            ):
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
        with (
            tempfile.TemporaryDirectory() as repo_root, patch.dict(
        os.environ, {"SECRET_SENTINEL_BASELINE_KEY": "test-key-" + "x" * 32}
    ), patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
            patch("secret_sentinel.cli.scan_paths", return_value=[issue]),
        ):
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
        with tempfile.TemporaryDirectory() as repo_root, patch.dict(
            os.environ, {"SECRET_SENTINEL_BASELINE_KEY": "test-key-" + "x" * 32}
        ), patch("secret_sentinel.cli.get_git_root", return_value=repo_root):
            with patch("secret_sentinel.cli.scan_paths", return_value=[original]):
                self.assertEqual(main(["--update-baseline", "--no-ai"]), 0)
            with patch(
                "secret_sentinel.cli.scan_paths",
                return_value=[original, new_issue],
            ):
                self.assertEqual(main(["--baseline", "--no-ai"]), 1)

    def test_main_baseline_requires_existing_file(self) -> None:
        """Baseline checks fail with an actionable message when no baseline exists."""
        with tempfile.TemporaryDirectory() as repo_root, patch.dict(
            os.environ, {"SECRET_SENTINEL_BASELINE_KEY": "test-key-" + "x" * 32}
        ), patch("secret_sentinel.cli.get_git_root", return_value=repo_root):
            self.assertEqual(main(["--baseline", "--no-ai"]), 1)

    def test_main_baseline_requires_key(self) -> None:
        """Baseline operations fail clearly when the key is not configured."""
        with (
            tempfile.TemporaryDirectory() as repo_root,
            patch.dict(os.environ, {"SECRET_SENTINEL_BASELINE_KEY": ""}),
            patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
        ):
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
            with (
                patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
                patch("secret_sentinel.cli.scan_git_history", return_value=[issue]) as scan,
            ):
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
            with (
                patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
                patch("secret_sentinel.cli.scan_git_history", return_value=[]) as scan,
            ):
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
            with (
                patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
                patch("secret_sentinel.cli.scan_paths", return_value=[]) as scan,
            ):
                self.assertEqual(main(["--diff", "HEAD~1", "--no-ai"]), 0)
            self.assertEqual(scan.call_args.kwargs["diff_base"], "HEAD~1")

    def test_main_commit_range_forwards_revisions_and_records_history(self) -> None:
        """Commit-range scans forward both revisions and record scan type."""
        issue = {
            "source": "settings.py",
            "line": 1,
            "matcher": "AWS Secret Access Key",
            "value": DUMMY_AWS,
            "snippet": f'key = "{DUMMY_AWS}"',
            "confidence": "high",
            "severity": "CRITICAL",
            "commit": "0123456789abcdef",
        }
        with tempfile.TemporaryDirectory() as repo_root:
            history = ScanHistory(repo_root)
            with (
                patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
                patch(
            "secret_sentinel.cli.scan_git_commit_range",
            return_value=[issue],
        ) as scan,
            ):
                self.assertEqual(
                    main(["--commit-range", "origin/main", "HEAD", "--no-ai"]),
                    1,
                )

            scan.assert_called_once()
            self.assertEqual(scan.call_args.args[1:3], ("origin/main", "HEAD"))
            self.assertEqual(history.get_history()[0]["scan_type"], "git-range")

    def test_main_commit_range_rejects_other_scan_modes(self) -> None:
        """Commit ranges must not be silently combined with other scan modes."""
        with patch("secret_sentinel.cli.get_git_root", return_value=None):
            self.assertEqual(
                main(["--commit-range", "origin/main", "HEAD", "--diff", "HEAD~1"]),
                2,
            )
            self.assertEqual(
                main(["--commit-range", "origin/main", "HEAD", "src/"]),
                2,
            )
            self.assertEqual(
                main(["--commit-range", "origin/main", "HEAD", "--history"]),
                2,
            )

    def test_main_commit_range_reports_errors_without_details(self) -> None:
        """Range scan errors use a generic message that avoids revision data."""
        with tempfile.TemporaryDirectory() as repo_root:
            output = StringIO()
            with (
                patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
                patch(
                    "secret_sentinel.cli.scan_git_commit_range",
                    side_effect=RuntimeError("internal detail"),
                ),
                redirect_stdout(output),
            ):
                self.assertEqual(
                    main(["--commit-range", "private-revision", "HEAD"]), 1
                )

        self.assertIn("Commit range scan failed", output.getvalue())
        self.assertNotIn("internal detail", output.getvalue())

    def test_main_git_history_scan_reports_errors(self) -> None:
        """History scan errors should fail explicitly with a generic message."""
        with (
            tempfile.TemporaryDirectory() as repo_root,
            patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
            patch(
            "secret_sentinel.cli.scan_git_history",
            side_effect=RuntimeError("internal detail"),
        ),
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
                self.assertEqual(main(["--install-pre-push-hook"]), 0)
                self.assertEqual(main(["--uninstall-pre-push-hook"]), 0)

    def test_main_pre_push_scan_blocks_findings_without_leaking_values(self) -> None:
        """The hook entry point scans pushed refs and safely formats findings."""
        issue = {
            "source": "config.py",
            "line": 1,
            "matcher": "AWS Secret Access Key",
            "value": DUMMY_AWS,
            "snippet": f'key = "{DUMMY_AWS}"',
            "confidence": "high",
            "severity": "CRITICAL",
        }
        output = StringIO()
        with tempfile.TemporaryDirectory() as repo_root:
            with (
                patch(
                    "secret_sentinel.cli.get_git_root", return_value=repo_root
                ),
                patch(
                    "secret_sentinel.cli.sys.stdin",
                    StringIO(
                        f"refs/heads/main {'a' * 40} "
                        f"refs/heads/main {'0' * 40}\n"
                    ),
                ),
                patch(
                    "secret_sentinel.cli.scan_git_push_updates",
                    return_value=[issue],
                ),
                redirect_stdout(output),
            ):
                self.assertEqual(main(["--pre-push"]), 1)
            record = ScanHistory(repo_root).get_history(limit=1)[0]

        self.assertIn("Detected potential secrets (1)", output.getvalue())
        self.assertIn("[REDACTED]", output.getvalue())
        self.assertNotIn(DUMMY_AWS, output.getvalue())
        self.assertEqual(record["scan_type"], "pre-push")
        self.assertEqual(record["status"], "blocked")

    def test_main_pre_push_scan_fails_closed_when_history_cannot_be_recorded(
        self,
    ) -> None:
        """A failure to persist the scan result prevents the push."""
        output = StringIO()
        with (
            tempfile.TemporaryDirectory() as repo_root,
            patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
            patch("secret_sentinel.cli.sys.stdin", StringIO("")),
            patch("secret_sentinel.cli.scan_git_push_updates", return_value=[]),
            patch(
                "secret_sentinel.cli.ScanHistory.record_scan",
                side_effect=OSError("storage unavailable"),
            ),
            redirect_stdout(output),
        ):
            self.assertEqual(main(["--pre-push"]), 1)

        self.assertIn("could not record history", output.getvalue())

    def test_main_pre_push_scan_reports_invalid_update_data(self) -> None:
        """An invalid update stream blocks the push without disclosing details."""
        output = StringIO()
        with (
            patch("secret_sentinel.cli.get_git_root", return_value="/repo"),
            patch("secret_sentinel.cli.sys.stdin", StringIO("bad input\n")),
            redirect_stdout(output),
        ):
            self.assertEqual(main(["--pre-push"]), 1)
        self.assertIn("Pre-push scan failed", output.getvalue())
        self.assertNotIn("bad input", output.getvalue())

    def test_main_doctor_reports_missing_repository(self) -> None:
        """Doctor should explain when it is run outside a Git repository."""
        output = StringIO()
        with (
            patch("secret_sentinel.cli.get_git_root", return_value=None),
            redirect_stdout(output),
        ):
            self.assertEqual(main(["--doctor"]), 1)
        self.assertIn("Git repository: not found", output.getvalue())

    def test_main_audit_suppressions_reports_clean_directive_without_leaking(self) -> None:
        """A documented, used suppression passes audit without exposing its value."""
        with tempfile.TemporaryDirectory() as repo_root:
            secret = DUMMY_AWS
            Path(repo_root, "fixture.py").write_text(
                f'aws_key = "{secret}"  # secret-sentinel: ignore '
                "reason: synthetic test fixture; expires: 2999-12-31\n",
                encoding="utf-8",
            )
            output = StringIO()
            with (
                patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
                redirect_stdout(output),
            ):
                result = main(["--audit-suppressions"])

        self.assertEqual(result, 0)
        self.assertIn("fixture.py:1 [ACTIVE]", output.getvalue())
        self.assertIn(
            "All 1 suppression(s) are documented and in use.", output.getvalue()
        )
        self.assertNotIn(secret, output.getvalue())

    def test_main_audit_suppressions_fails_for_directives_needing_review(self) -> None:
        """An undocumented and unused directive is reported as a failing audit."""
        with tempfile.TemporaryDirectory() as repo_root:
            Path(repo_root, "fixture.py").write_text(
                "# secret-sentinel: ignore\n", encoding="utf-8"
            )
            output = StringIO()
            with (
                patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
                redirect_stdout(output),
            ):
                result = main(["--audit-suppressions"])

        self.assertEqual(result, 1)
        self.assertIn(
            "[MISSING REASON, MISSING EXPIRY, UNUSED]", output.getvalue()
        )
        self.assertIn("1 suppression(s) need review", output.getvalue())

    def test_main_audit_suppressions_reports_empty_repository(self) -> None:
        """An audit with no directives succeeds with a clear message."""
        with (
            tempfile.TemporaryDirectory() as repo_root,
            patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
            redirect_stdout(StringIO()) as output,
        ):
            self.assertEqual(main(["--audit-suppressions"]), 0)
        self.assertIn("No inline suppression directives found.", output.getvalue())

    def test_main_audit_suppressions_supports_json_and_sarif_output(self) -> None:
        """Machine-readable audit formats preserve status and safe locations."""
        with tempfile.TemporaryDirectory() as repo_root:
            Path(repo_root, "fixture.py").write_text(
                "# secret-sentinel: ignore\n", encoding="utf-8"
            )
            with patch("secret_sentinel.cli.get_git_root", return_value=repo_root):
                json_output = StringIO()
                with redirect_stdout(json_output):
                    self.assertEqual(
                        main(["--audit-suppressions", "--format", "json"]), 1
                    )
                json_report = json.loads(json_output.getvalue())
                self.assertEqual(json_report["status"], "review")
                self.assertEqual(json_report["needs_review"], 1)

                sarif_output = StringIO()
                with redirect_stdout(sarif_output):
                    self.assertEqual(
                        main(["--audit-suppressions", "--format", "sarif"]), 1
                    )
                sarif_report = json.loads(sarif_output.getvalue())
                result = sarif_report["runs"][0]["results"][0]
                self.assertEqual(result["ruleId"], "suppression-review")
                self.assertEqual(result["level"], "warning")

    def test_main_audit_suppressions_writes_report_to_file(self) -> None:
        """Audit output should support report files without stdout duplication."""
        with tempfile.TemporaryDirectory() as repo_root:
            Path(repo_root, "fixture.py").write_text(
                "# secret-sentinel: ignore\n", encoding="utf-8"
            )
            report_path = os.path.join(repo_root, "report.json")
            output = StringIO()
            with (
                patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
                redirect_stdout(output),
            ):
                self.assertEqual(
                    main(
                        [
                            "--audit-suppressions",
                            "--format",
                            "json",
                            "--output",
                            report_path,
                        ]
                    ),
                    1,
                )

            self.assertEqual(output.getvalue(), "")
            report = json.loads(Path(report_path).read_text(encoding="utf-8"))
            self.assertEqual(report["needs_review"], 1)

    def test_main_audit_suppressions_reports_output_file_errors(self) -> None:
        """An unwritable report path should fail explicitly."""
        with (
            tempfile.TemporaryDirectory() as repo_root,
            patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
            redirect_stdout(StringIO()),
        ):
            self.assertEqual(
                main(
                    [
                        "--audit-suppressions",
                        "--format",
                        "json",
                        "--output",
                        os.path.join(repo_root, "missing", "report.json"),
                    ]
                ),
                1,
            )

    def test_main_audit_suppressions_rejects_other_modes(self) -> None:
        """Suppression audit cannot silently ignore another command's options."""
        with patch("secret_sentinel.cli.get_git_root", return_value=None):
            self.assertEqual(main(["--audit-suppressions", "--doctor"]), 2)

    def test_main_setup_commands_reject_unrelated_options(self) -> None:
        """Setup commands should reject options that would otherwise be ignored."""
        with patch("secret_sentinel.cli.get_git_root", return_value=None):
            self.assertEqual(main(["--doctor", "--staged"]), 2)
            self.assertEqual(main(["--yes"]), 2)

    def test_main_doctor_reports_safe_repository_status(self) -> None:
        """Doctor should report optional setup without changing repository files."""
        with tempfile.TemporaryDirectory() as repo_root:
            os.makedirs(os.path.join(repo_root, ".git", "hooks"))
            output = StringIO()
            with (
                patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
                redirect_stdout(output),
            ):
                self.assertEqual(main(["--doctor"]), 0)
            report = output.getvalue()
            self.assertIn("Configuration: defaults active", report)
            self.assertIn("Pre-commit hook: not installed (optional)", report)
            self.assertIn("Pre-push hook: not installed (optional)", report)
            self.assertIn("secret-sentinel --init", report)
            self.assertIn("--install-pre-push-hook", report)
            self.assertIn("Baseline: not configured (optional)", report)
            self.assertFalse(os.path.exists(os.path.join(repo_root, ".secret-sentinel.ini")))
            self.assertFalse(os.path.exists(os.path.join(repo_root, ".git", "hooks", "pre-commit")))

    def test_main_doctor_reports_managed_pre_push_hook(self) -> None:
        """Doctor recognizes the installed pre-push hook without exposing content."""
        with tempfile.TemporaryDirectory() as repo_root:
            hooks_dir = Path(repo_root) / ".git" / "hooks"
            hooks_dir.mkdir(parents=True)
            (hooks_dir / "pre-push").write_text(
                "#!/usr/bin/env python3\n"
                "# secret-sentinel managed pre-push hook\n"
                "private_hook_value\n",
                encoding="utf-8",
            )
            output = StringIO()
            with (
                patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
                redirect_stdout(output),
            ):
                self.assertEqual(main(["--doctor"]), 0)

            self.assertIn("Pre-push hook: installed", output.getvalue())
            self.assertNotIn("private_hook_value", output.getvalue())
            self.assertNotIn("--install-pre-push-hook", output.getvalue())

    def test_main_doctor_reports_effective_scan_settings(self) -> None:
        """Doctor should summarize effective settings without exposing patterns."""
        with tempfile.TemporaryDirectory() as repo_root:
            config_path = Path(repo_root) / ".secret-sentinel.ini"
            config_path.write_text(
                "[secret-sentinel]\n"
                "ignore_paths = private-fixtures/*\n"
                "fail_on = HIGH\n"
                "[custom_rules]\n"
                "Private Token = CRITICAL | private_[A-Za-z0-9]+\n",
                encoding="utf-8",
            )
            output = StringIO()
            with (
                patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
                redirect_stdout(output),
            ):
                self.assertEqual(main(["--doctor"]), 0)

            report = output.getvalue()
            self.assertIn("fail on HIGH", report)
            self.assertIn("ignored path patterns", report)
            self.assertIn("1 custom rules", report)
            self.assertNotIn("private-fixtures", report)
            self.assertNotIn("private_[A-Za-z0-9]", report)
            self.assertIn("Doctor checks passed.", report)

    def test_main_doctor_gives_actionable_unmanaged_hook_guidance(self) -> None:
        """Doctor should explain how to handle an existing unmanaged hook."""
        with tempfile.TemporaryDirectory() as repo_root:
            hooks_dir = Path(repo_root) / ".git" / "hooks"
            hooks_dir.mkdir(parents=True)
            hook_path = hooks_dir / "pre-commit"
            hook_path.write_text("#!/bin/sh\necho existing\n", encoding="utf-8")
            output = StringIO()
            with (
                patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
                redirect_stdout(output),
            ):
                self.assertEqual(main(["--doctor"]), 0)

            report = output.getvalue()
            self.assertIn("another hook is present", report)
            self.assertIn("combine the scanner with it manually", report)
            self.assertNotIn("secret-sentinel --init", report)

    def test_main_doctor_reports_missing_baseline_key_safely(self) -> None:
        """Doctor should tell users how to configure a key without echoing it."""
        with tempfile.TemporaryDirectory() as repo_root:
            baseline_path = Path(repo_root) / ScanBaseline.DEFAULT_PATH
            baseline_path.parent.mkdir(parents=True)
            baseline_path.write_text(
                '{"version": 1, "fingerprints": []}\n', encoding="utf-8"
            )
            output = StringIO()
            with (
                patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
                patch.dict(os.environ, {ScanBaseline.KEY_ENVIRONMENT_VARIABLE: ""}),
                redirect_stdout(output),
            ):
                self.assertEqual(main(["--doctor"]), 0)

            report = output.getvalue()
            self.assertIn("key is missing or too short", report)
            self.assertIn(ScanBaseline.KEY_ENVIRONMENT_VARIABLE, report)
            self.assertIn("Doctor checks passed.", report)

    def test_main_doctor_validates_baseline_and_hides_key(self) -> None:
        """Doctor should validate a usable baseline without printing its key."""
        with tempfile.TemporaryDirectory() as repo_root:
            key = "test-key-" + "x" * 32
            output = StringIO()
            with (
                patch.dict(os.environ, {ScanBaseline.KEY_ENVIRONMENT_VARIABLE: key}),
                patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
                redirect_stdout(output),
            ):
                ScanBaseline(repo_root).save([])
                self.assertEqual(main(["--doctor"]), 0)

            self.assertIn(
                "Baseline: format valid; key meets minimum length",
                output.getvalue(),
            )
            self.assertNotIn(key, output.getvalue())

    def test_main_doctor_rejects_bad_baseline_without_leaking(self) -> None:
        """An invalid baseline should fail doctor without echoing its contents."""
        with tempfile.TemporaryDirectory() as repo_root:
            baseline_path = Path(repo_root) / ScanBaseline.DEFAULT_PATH
            baseline_path.parent.mkdir(parents=True)
            baseline_path.write_text("sensitive malformed payload", encoding="utf-8")
            key = "test-key-" + "x" * 32
            output = StringIO()
            with (
                patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
                patch.dict(os.environ, {ScanBaseline.KEY_ENVIRONMENT_VARIABLE: key}),
                redirect_stdout(output),
            ):
                self.assertEqual(main(["--doctor"]), 1)

            report = output.getvalue()
            self.assertIn("Baseline: could not be validated", report)
            self.assertIn("Doctor checks failed", report)
            self.assertNotIn("sensitive malformed payload", report)
            self.assertNotIn(key, report)

    def test_main_doctor_rejects_baseline_path_that_is_not_a_file(self) -> None:
        """A directory at the baseline location should not be reported as absent."""
        with tempfile.TemporaryDirectory() as repo_root:
            baseline_path = Path(repo_root) / ScanBaseline.DEFAULT_PATH
            baseline_path.mkdir(parents=True)
            output = StringIO()
            with (
                patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
                redirect_stdout(output),
            ):
                self.assertEqual(main(["--doctor"]), 1)

            self.assertIn("Baseline: expected a regular file", output.getvalue())
            self.assertIn("Doctor checks failed", output.getvalue())

    def test_main_setup_guides_baseline_without_creating_files(self) -> None:
        """Baseline guidance should explain key requirements without writing files."""
        with tempfile.TemporaryDirectory() as repo_root:
            stdin = MagicMock()
            stdin.isatty.return_value = True
            output = StringIO()
            with (
                patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
                patch("secret_sentinel.cli.sys.stdin", stdin),
                patch("builtins.input", return_value="2"),
                redirect_stdout(output),
            ):
                self.assertEqual(main(["--setup"]), 0)

            guidance = output.getvalue()
            self.assertIn("Review current findings", guidance)
            self.assertIn("SECRET_SENTINEL_BASELINE_KEY", guidance)
            self.assertIn("secrets.token_hex(32)", guidance)
            self.assertIn("secret-sentinel --update-baseline .", guidance)
            self.assertIn("not secret values", guidance)
            baseline_dir = os.path.join(repo_root, ".secret-sentinel")
            self.assertFalse(os.path.exists(baseline_dir))

    def test_main_setup_guides_github_actions(self) -> None:
        """CI setup should point to the documented workflow without side effects."""
        with tempfile.TemporaryDirectory() as repo_root:
            stdin = MagicMock()
            stdin.isatty.return_value = True
            output = StringIO()
            with (
                patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
                patch("secret_sentinel.cli.sys.stdin", stdin),
                patch("builtins.input", return_value="3"),
                redirect_stdout(output),
            ):
                self.assertEqual(main(["--setup"]), 0)

            self.assertIn("#github-actions", output.getvalue())
            self.assertFalse(os.path.exists(os.path.join(repo_root, ".github")))

    def test_main_setup_defaults_to_manual_scan_guidance(self) -> None:
        """Pressing enter at setup should suggest a safe manual scan."""
        with tempfile.TemporaryDirectory() as repo_root:
            stdin = MagicMock()
            stdin.isatty.return_value = True
            output = StringIO()
            with (
                patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
                patch("secret_sentinel.cli.sys.stdin", stdin),
                patch("builtins.input", return_value=""),
                redirect_stdout(output),
            ):
                self.assertEqual(main(["--setup"]), 0)
            self.assertIn("secret-sentinel .", output.getvalue())
            self.assertIn("secret-sentinel --staged", output.getvalue())

    def test_main_setup_guides_explicit_local_scan_choice(self) -> None:
        """Choice four should show local scan commands without changing files."""
        with tempfile.TemporaryDirectory() as repo_root:
            stdin = MagicMock()
            stdin.isatty.return_value = True
            output = StringIO()
            with (
                patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
                patch("secret_sentinel.cli.sys.stdin", stdin),
                patch("builtins.input", return_value="4"),
                redirect_stdout(output),
            ):
                self.assertEqual(main(["--setup"]), 0)

            self.assertIn("secret-sentinel .", output.getvalue())
            self.assertIn("secret-sentinel --staged", output.getvalue())
            self.assertEqual(os.listdir(repo_root), [])

    def test_main_setup_cancellation_makes_no_changes(self) -> None:
        """Cancelling at the setup menu should leave the repository unchanged."""
        with tempfile.TemporaryDirectory() as repo_root:
            stdin = MagicMock()
            stdin.isatty.return_value = True
            output = StringIO()
            with (
                patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
                patch("secret_sentinel.cli.sys.stdin", stdin),
                patch("builtins.input", side_effect=EOFError),
                redirect_stdout(output),
            ):
                self.assertEqual(main(["--setup"]), 0)

            self.assertIn("No changes were made.", output.getvalue())
            self.assertEqual(os.listdir(repo_root), [])

    def test_main_setup_requires_terminal(self) -> None:
        """Interactive setup should not make assumptions in non-interactive use."""
        stdin = MagicMock()
        stdin.isatty.return_value = False
        with (
            patch("secret_sentinel.cli.get_git_root", return_value="/repo"),
            patch("secret_sentinel.cli.sys.stdin", stdin),
        ):
            self.assertEqual(main(["--setup"]), 2)

    def test_main_setup_rejects_invalid_choice_without_changes(self) -> None:
        """An unknown setup selection should fail without changing repository files."""
        with tempfile.TemporaryDirectory() as repo_root:
            stdin = MagicMock()
            stdin.isatty.return_value = True
            with (
                patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
                patch("secret_sentinel.cli.sys.stdin", stdin),
                patch("builtins.input", return_value="6"),
            ):
                self.assertEqual(main(["--setup"]), 2)
            self.assertEqual(os.listdir(repo_root), [])

    def test_main_setup_rejects_scan_options(self) -> None:
        """Setup mode should reject options that would otherwise be ignored."""
        with patch("secret_sentinel.cli.get_git_root", return_value=None):
            self.assertEqual(main(["--setup", "--staged"]), 2)

    def test_main_setup_requires_git_repository(self) -> None:
        """Setup guide should explain when no repository is available."""
        with patch("secret_sentinel.cli.get_git_root", return_value=None):
            self.assertEqual(main(["--setup"]), 1)

    def test_main_setup_can_install_hook_after_selection_and_confirmation(self) -> None:
        """Hook installation requires a menu selection and a separate confirmation."""
        with tempfile.TemporaryDirectory() as repo_root:
            hooks_dir = os.path.join(repo_root, ".git", "hooks")
            os.makedirs(hooks_dir)
            stdin = MagicMock()
            stdin.isatty.return_value = True
            with (
                patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
                patch("secret_sentinel.cli.sys.stdin", stdin),
                patch("builtins.input", side_effect=["1", "yes"]),
            ):
                self.assertEqual(main(["--setup"]), 0)
            hook_path = os.path.join(hooks_dir, "pre-commit")
            with open(hook_path, "r", encoding="utf-8") as handle:
                self.assertIn("secret-sentinel managed hook", handle.read())

    def test_main_setup_can_install_pre_push_hook(self) -> None:
        """Guided setup confirms and installs the optional pre-push hook."""
        with tempfile.TemporaryDirectory() as repo_root:
            hooks_dir = os.path.join(repo_root, ".git", "hooks")
            os.makedirs(hooks_dir)
            stdin = MagicMock()
            stdin.isatty.return_value = True
            with (
                patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
                patch("secret_sentinel.cli.sys.stdin", stdin),
                patch("builtins.input", side_effect=["5", "yes"]),
            ):
                self.assertEqual(main(["--setup"]), 0)

            hook_path = os.path.join(hooks_dir, "pre-push")
            self.assertIn(
                "secret-sentinel managed pre-push hook",
                Path(hook_path).read_text(encoding="utf-8"),
            )

    def test_main_setup_cancellation_does_not_install_hook(self) -> None:
        """Declining hook installation should not change repository files."""
        with tempfile.TemporaryDirectory() as repo_root:
            hooks_dir = os.path.join(repo_root, ".git", "hooks")
            os.makedirs(hooks_dir)
            stdin = MagicMock()
            stdin.isatty.return_value = True
            output = StringIO()
            with (
                patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
                patch("secret_sentinel.cli.sys.stdin", stdin),
                patch("builtins.input", side_effect=["1", "no"]),
                redirect_stdout(output),
            ):
                self.assertEqual(main(["--setup"]), 0)

            self.assertIn("No changes were made.", output.getvalue())
            self.assertFalse(os.path.exists(os.path.join(hooks_dir, "pre-commit")))
            self.assertFalse(
                os.path.exists(os.path.join(repo_root, ".secret-sentinel.ini"))
            )

    def test_main_setup_preserves_existing_hook(self) -> None:
        """Guided setup should not overwrite an existing pre-commit hook."""
        with tempfile.TemporaryDirectory() as repo_root:
            hooks_dir = os.path.join(repo_root, ".git", "hooks")
            os.makedirs(hooks_dir)
            hook_path = os.path.join(hooks_dir, "pre-commit")
            original = "#!/bin/sh\necho keep\n"
            with open(hook_path, "w", encoding="utf-8") as handle:
                handle.write(original)
            stdin = MagicMock()
            stdin.isatty.return_value = True
            with (
                patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
                patch("secret_sentinel.cli.sys.stdin", stdin),
                patch("builtins.input", side_effect=["1", "yes"]),
            ):
                self.assertEqual(main(["--setup"]), 1)

            with open(hook_path, "r", encoding="utf-8") as handle:
                self.assertEqual(handle.read(), original)

    def test_main_doctor_hides_configuration_errors(self) -> None:
        """Doctor should not print configuration contents when parsing fails."""
        with tempfile.TemporaryDirectory() as repo_root:
            with open(os.path.join(repo_root, ".secret-sentinel.ini"), "w", encoding="utf-8") as handle:
                handle.write("[custom_rules]\nBroken = HIGH | [\n")
            output = StringIO()
            with (
                patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
                redirect_stdout(output),
            ):
                self.assertEqual(main(["--doctor"]), 1)
            self.assertIn("Configuration: could not be loaded", output.getvalue())
            self.assertNotIn("HIGH | [", output.getvalue())

    def test_main_init_requires_confirmation_non_interactively(self) -> None:
        """Init should not make changes without --yes in non-interactive use."""
        with tempfile.TemporaryDirectory() as repo_root:
            hooks_dir = os.path.join(repo_root, ".git", "hooks")
            os.makedirs(hooks_dir)
            with (
                patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
                patch("secret_sentinel.cli.sys.stdin") as stdin,
            ):
                stdin.isatty.return_value = False
                self.assertEqual(main(["--init"]), 2)
            self.assertFalse(os.path.exists(os.path.join(hooks_dir, "pre-commit")))

    def test_main_init_installs_hook_after_confirmation(self) -> None:
        """Init should install its hook after explicit non-interactive confirmation."""
        with tempfile.TemporaryDirectory() as repo_root:
            hooks_dir = os.path.join(repo_root, ".git", "hooks")
            os.makedirs(hooks_dir)
            output = StringIO()
            with (
                patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
                redirect_stdout(output),
            ):
                self.assertEqual(main(["--init", "--yes"]), 0)
            with open(os.path.join(hooks_dir, "pre-commit"), "r", encoding="utf-8") as handle:
                self.assertIn("secret-sentinel managed hook", handle.read())
            self.assertFalse(os.path.exists(os.path.join(repo_root, ".secret-sentinel.ini")))
            self.assertIn("Setup complete", output.getvalue())
            self.assertIn("secret-sentinel .", output.getvalue())
            self.assertIn("secret-sentinel --doctor", output.getvalue())

    def test_main_init_does_not_replace_existing_hook(self) -> None:
        """Init should preserve an unmanaged hook and report the conflict."""
        with tempfile.TemporaryDirectory() as repo_root:
            hooks_dir = os.path.join(repo_root, ".git", "hooks")
            os.makedirs(hooks_dir)
            hook_path = os.path.join(hooks_dir, "pre-commit")
            with open(hook_path, "w", encoding="utf-8") as handle:
                handle.write("#!/bin/sh\necho keep\n")
            with patch("secret_sentinel.cli.get_git_root", return_value=repo_root):
                self.assertEqual(main(["--init", "--yes"]), 1)
            with open(hook_path, "r", encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "#!/bin/sh\necho keep\n")

    def test_main_init_leaves_managed_hook_unchanged(self) -> None:
        """Init should recognize an existing managed hook without rewriting it."""
        with tempfile.TemporaryDirectory() as repo_root:
            hooks_dir = os.path.join(repo_root, ".git", "hooks")
            os.makedirs(hooks_dir)
            hook_path = os.path.join(hooks_dir, "pre-commit")
            original = "# secret-sentinel managed hook\ncustomized locally\n"
            with open(hook_path, "w", encoding="utf-8") as handle:
                handle.write(original)
            with patch("secret_sentinel.cli.get_git_root", return_value=repo_root):
                self.assertEqual(main(["--init", "--yes"]), 0)
            with open(hook_path, "r", encoding="utf-8") as handle:
                self.assertEqual(handle.read(), original)

    def test_main_init_rejects_invalid_configuration_without_changes(self) -> None:
        """Init should validate configuration before installing the hook."""
        with tempfile.TemporaryDirectory() as repo_root:
            hooks_dir = os.path.join(repo_root, ".git", "hooks")
            os.makedirs(hooks_dir)
            with open(
                os.path.join(repo_root, ".secret-sentinel.ini"),
                "w",
                encoding="utf-8",
            ) as handle:
                handle.write("[custom_rules]\nBroken = HIGH | [\n")
            with patch("secret_sentinel.cli.get_git_root", return_value=repo_root):
                self.assertEqual(main(["--init", "--yes"]), 1)
            self.assertFalse(os.path.exists(os.path.join(hooks_dir, "pre-commit")))

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
            self.assertTrue(any(i["matcher"] == "AWS Access Key ID" for i in issues))

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

            with (
                patch("secret_sentinel.cli.get_git_root", return_value=tmpdir),
                patch(
            "secret_sentinel.cli.validate_issues",
            return_value=[],
        ) as validate,
            ):
                issues = cli_scan_paths([secret_file], no_ai=False, staged=False, debug=False)
                self.assertEqual(issues, [])
                self.assertTrue(validate.call_args.kwargs["allow_cloud"])

    def test_main_format_json(self) -> None:
        """Main with --format json should return exit code 0 when clean."""
        with (
            patch("secret_sentinel.cli.scan_paths", return_value=[]),
            patch("secret_sentinel.cli.get_git_root", return_value=None),
        ):
            self.assertEqual(main(["--format", "json", "--no-ai"]), 0)

    def test_main_coverage_requires_explicit_disk_paths(self) -> None:
        """Coverage mode rejects implicit staged scans."""
        with patch("secret_sentinel.cli.get_git_root", return_value=None):
            self.assertEqual(main(["--coverage"]), 2)
            self.assertEqual(main(["--strict-coverage"]), 2)

    def test_main_reports_explicit_disk_scan_coverage(self) -> None:
        """Coverage counts flow from disk scanning into machine-readable output."""
        with tempfile.TemporaryDirectory() as repo_root:
            with open(os.path.join(repo_root, "clean.py"), "w", encoding="utf-8") as handle:
                handle.write("value = 1\n")
            with open(os.path.join(repo_root, "binary.bin"), "wb") as handle:
                handle.write(b"\x00binary")

            output = StringIO()
            with (
                redirect_stdout(output),
                patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
            ):
                result = main(
                    [repo_root, "--coverage", "--no-ai", "--format", "json"]
                )

        report = json.loads(output.getvalue())
        self.assertEqual(result, 0)
        self.assertEqual(report["coverage"]["scanned_files"], 1)
        self.assertEqual(report["coverage"]["binary_files"], 1)

    def test_main_strict_coverage_allows_binary_files(self) -> None:
        """Intentional binary skips do not fail strict coverage."""
        with tempfile.TemporaryDirectory() as repo_root:
            with open(os.path.join(repo_root, "binary.bin"), "wb") as handle:
                handle.write(b"\x00binary")

            output = StringIO()
            with (
                redirect_stdout(output),
                patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
            ):
                result = main(
                    [repo_root, "--strict-coverage", "--no-ai", "--format", "json"]
                )

        report = json.loads(output.getvalue())
        self.assertEqual(result, 0)
        self.assertTrue(report["scan_complete"])
        self.assertEqual(report["coverage"]["binary_files"], 1)

    def test_main_fails_incomplete_disk_scan_and_reports_coverage(self) -> None:
        """Missing paths cannot produce a successful all-clear scan."""
        with tempfile.TemporaryDirectory() as repo_root:
            missing_path = os.path.join(repo_root, "missing.py")
            output = StringIO()
            with (
                patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
                redirect_stdout(output),
            ):
                result = main([missing_path, "--no-ai"])
            history_status = ScanHistory(repo_root).get_history()[0]["status"]

        report = output.getvalue()
        self.assertEqual(result, 1)
        self.assertIn("Scan incomplete", report)
        self.assertIn("1 missing", report)
        self.assertNotIn("All clear!", report)
        self.assertEqual(history_status, "incomplete")

    def test_main_json_marks_incomplete_disk_scan(self) -> None:
        """Machine-readable reports mark unread paths as incomplete."""
        with tempfile.TemporaryDirectory() as repo_root:
            missing_path = os.path.join(repo_root, "missing.py")
            output = StringIO()
            with (
                patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
                redirect_stdout(output),
            ):
                result = main([missing_path, "--no-ai", "--format", "json"])

        report = json.loads(output.getvalue())
        self.assertEqual(result, 1)
        self.assertFalse(report["scan_complete"])
        self.assertEqual(report["coverage"]["missing_paths"], 1)

    def test_main_strict_coverage_fails_on_oversized_files(self) -> None:
        """Strict coverage fails when requested files cannot be scanned by size."""
        with tempfile.TemporaryDirectory() as repo_root:
            output = StringIO()
            coverage = ScanCoverage(oversized_files=1)
            with (
                patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
                patch("secret_sentinel.cli.ScanCoverage", return_value=coverage),
                patch("secret_sentinel.cli.scan_paths", return_value=[]),
                redirect_stdout(output),
            ):
                result = main(
                    [repo_root, "--strict-coverage", "--no-ai", "--format", "json"]
                )

            history_status = ScanHistory(repo_root).get_history()[0]["status"]

        report = json.loads(output.getvalue())
        self.assertEqual(result, 1)
        self.assertFalse(report["scan_complete"])
        self.assertEqual(report["coverage"]["oversized_files"], 1)
        self.assertEqual(history_status, "incomplete")

    def test_main_reports_staged_scan_failures_without_details(self) -> None:
        """Git index read failures return a visible nonzero scan result."""
        output = StringIO()
        with (
            patch(
                "secret_sentinel.cli.scan_paths",
                side_effect=RuntimeError("index details"),
            ),
            redirect_stdout(output),
        ):
            result = main(["--staged", "--no-ai"])

        self.assertEqual(result, 1)
        self.assertIn("Scan failed", output.getvalue())
        self.assertNotIn("index details", output.getvalue())

    def test_main_does_not_update_baseline_for_incomplete_scan(self) -> None:
        """Incomplete scans cannot establish a baseline that hides unchecked files."""
        with tempfile.TemporaryDirectory() as repo_root:
            missing_path = os.path.join(repo_root, "missing.py")
            output = StringIO()
            with (
                patch("secret_sentinel.cli.get_git_root", return_value=repo_root),
                redirect_stdout(output),
            ):
                result = main(
                    [missing_path, "--no-ai", "--update-baseline"]
                )

            baseline_path = Path(repo_root) / ".secret-sentinel" / "baseline.json"
            self.assertFalse(baseline_path.exists())

        self.assertEqual(result, 1)
        self.assertIn("Baseline not updated", output.getvalue())

    def test_main_format_sarif(self) -> None:
        """Main with --format sarif should return exit code 0 when clean."""
        with (
            patch("secret_sentinel.cli.scan_paths", return_value=[]),
            patch("secret_sentinel.cli.get_git_root", return_value=None),
        ):
            self.assertEqual(main(["--format", "sarif", "--no-ai"]), 0)

    def test_main_output_to_file(self) -> None:
        """Main with --output should write report to target file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = os.path.join(tmpdir, "report.json")
            with (
                patch("secret_sentinel.cli.scan_paths", return_value=[]),
                patch("secret_sentinel.cli.get_git_root", return_value=None),
            ):
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
        with (
            patch("secret_sentinel.cli.scan_paths", return_value=mock_medium_issue),
            patch("secret_sentinel.cli.get_git_root", return_value=None),
        ):
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
        with (
            patch("secret_sentinel.cli.scan_paths", return_value=mock_critical_issue),
            patch("secret_sentinel.cli.get_git_root", return_value=None),
        ):
            self.assertEqual(main(["--fail-on", "HIGH", "--no-ai"]), 1)


if __name__ == "__main__":
    unittest.main()
