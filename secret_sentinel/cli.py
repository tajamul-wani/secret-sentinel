"""Command-line interface for Secret Sentinel."""

import argparse
import configparser
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import __version__
from .ai_validator import validate_issues
from .baseline import ScanBaseline
from .config import CustomRule, SecretSentinelConfig
from .formatters import (
    format_json,
    format_sarif,
    format_suppression_audit_json,
    format_suppression_audit_sarif,
    format_suppression_audit_text,
    format_text,
)
from .history import ScanHistory
from .risk_scoring import SeverityLevel, calculate_overall_severity
from .scanner import (
    ScanCoverage,
    audit_suppressions_in_repo,
    get_git_root,
    get_staged_content,
    scan_git_commit_range,
    scan_git_diff,
    scan_git_history,
    scan_git_push_updates,
    scan_paths as scan_disk_paths,
    scan_staged_files,
)

logger = logging.getLogger("secret_sentinel")
HOOK_MARKER = "# secret-sentinel managed hook"
PRE_PUSH_HOOK_MARKER = "# secret-sentinel managed pre-push hook"


def setup_logging(debug: bool = False) -> None:
    """Configure logging format and level.

    Args:
        debug: Whether debug mode is enabled.
    """
    level = logging.DEBUG if debug else logging.INFO
    formatter = logging.Formatter("%(levelname)s: %(message)s" if debug else "%(message)s")
    handler = logging.StreamHandler(sys.stdout if not debug else sys.stderr)
    handler.setFormatter(formatter)
    handler.setLevel(level)

    logger.handlers.clear()
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser.

    Returns:
        Configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        prog="secret-sentinel",
        description="Local secret scanner with Git pre-commit and pre-push hooks.",
        epilog=(
            "Quick start:\n"
            "  secret-sentinel --setup   Choose a setup path\n"
            "  secret-sentinel .         Scan the working tree\n"
            "  secret-sentinel --staged  Scan staged changes\n"
            "  secret-sentinel --doctor  Check repository setup"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="Paths to scan. If omitted and --staged is not set, scans staged files in current Git repo.",
    )
    parser.add_argument(
        "--staged",
        action="store_true",
        help="Scan staged Git files instead of disk paths.",
    )
    parser.add_argument(
        "--git-history",
        action="store_true",
        help="Scan commits reachable from HEAD for secrets.",
    )
    parser.add_argument(
        "--diff",
        metavar="BASE",
        help="Scan added lines in the working tree diff against BASE.",
    )
    parser.add_argument(
        "--commit-range",
        nargs=2,
        metavar=("BASE", "HEAD"),
        help="Scan commits from BASE through HEAD, including intermediate history.",
    )
    parser.add_argument(
        "--all-refs",
        action="store_true",
        help="With --git-history, include commits reachable from all local Git refs.",
    )
    baseline_group = parser.add_mutually_exclusive_group()
    baseline_group.add_argument(
        "--baseline",
        action="store_true",
        help="Ignore findings already recorded in .secret-sentinel/baseline.json.",
    )
    baseline_group.add_argument(
        "--update-baseline",
        action="store_true",
        help="Record current findings in .secret-sentinel/baseline.json and exit successfully.",
    )
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Skip AI context validation and rely on local regex/entropy scanning only.",
    )
    parser.add_argument(
        "--coverage",
        action="store_true",
        help="Report scanned and skipped paths for an explicit on-disk path scan.",
    )
    parser.add_argument(
        "--install-hook",
        action="store_true",
        help="Install secret-sentinel as a Git pre-commit hook in the current repository.",
    )
    parser.add_argument(
        "--uninstall-hook",
        action="store_true",
        help="Remove the secret-sentinel Git pre-commit hook if installed.",
    )
    parser.add_argument(
        "--install-pre-push-hook",
        action="store_true",
        help="Install Secret Sentinel as a Git pre-push hook.",
    )
    parser.add_argument(
        "--uninstall-pre-push-hook",
        action="store_true",
        help="Remove the Secret Sentinel Git pre-push hook if installed.",
    )
    parser.add_argument(
        "--pre-push",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print debug information during scanning.",
    )
    parser.add_argument(
        "--history",
        action="store_true",
        help="Show scan history.",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Show scan statistics.",
    )
    parser.add_argument(
        "--history-limit",
        type=int,
        default=10,
        help="Number of history records to show (default: 10).",
    )
    parser.add_argument(
        "--clear-history",
        action="store_true",
        help="Clear all scan history.",
    )
    parser.add_argument(
        "--doctor",
        action="store_true",
        help="Check repository, configuration, hook, and optional baseline setup.",
    )
    parser.add_argument(
        "--audit-suppressions",
        action="store_true",
        help="Review inline suppression reasons, expiries, and usage.",
    )
    parser.add_argument(
        "--setup",
        action="store_true",
        help="Interactively choose a local scan, hook, baseline, or CI setup path.",
    )
    parser.add_argument(
        "--init",
        action="store_true",
        help="Set up the Git pre-commit hook after confirmation.",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Confirm setup changes non-interactively; use with --init.",
    )
    parser.add_argument(
        "--fail-on",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default=None,
        help="Minimum severity level required to block commit or exit with code 1 (default: LOW).",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format: text, json, or sarif (default: text).",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Write findings report to specified file instead of stdout.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"secret-sentinel {__version__}",
    )
    return parser


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse command line arguments.

    Args:
        argv: Optional list of CLI argument strings. Uses sys.argv[1:] if None.

    Returns:
        Parsed Namespace object.
    """
    parser = build_parser()
    return parser.parse_args(argv)


def parse_args_from(argv: List[str]) -> argparse.Namespace:
    """Parse arguments from a specified list.

    Args:
        argv: List of arguments.

    Returns:
        Parsed Namespace object.
    """
    return parse_args(argv)


def install_git_hook(repo_root: str) -> None:
    """Install the Git pre-commit hook in the repository.

    Args:
        repo_root: Root path of the Git repository.
    """
    hook_contents = """#!/usr/bin/env python3
import sys
from pathlib import Path

""" + HOOK_MARKER + """
# Git runs hooks from the active worktree root.
repo_root = Path.cwd().resolve()
sys.path.insert(0, str(repo_root))

from secret_sentinel.cli import main

if __name__ == "__main__":
    sys.exit(main(["--no-ai", "--staged"]))
"""
    _install_git_hook(repo_root, "pre-commit", HOOK_MARKER, hook_contents)


def install_git_pre_push_hook(repo_root: str) -> None:
    """Install the Git pre-push hook in the repository."""
    hook_contents = """#!/usr/bin/env python3
import sys
from pathlib import Path

""" + PRE_PUSH_HOOK_MARKER + """
repo_root = Path.cwd().resolve()
sys.path.insert(0, str(repo_root))

from secret_sentinel.cli import main

if __name__ == "__main__":
    sys.exit(main(["--pre-push"]))
"""
    _install_git_hook(
        repo_root, "pre-push", PRE_PUSH_HOOK_MARKER, hook_contents
    )


def _install_git_hook(
    repo_root: str,
    hook_name: str,
    marker: str,
    hook_contents: str,
) -> None:
    """Install a managed Git hook without replacing an unmanaged hook."""
    try:
        hook_path = _get_git_hook_path(repo_root, hook_name)
        if not hook_path.parent.is_dir():
            logger.error("No Git hooks directory found in repository.")
            sys.exit(1)
        if os.path.lexists(hook_path):
            if hook_path.is_symlink():
                logger.error("An existing %s hook cannot be replaced.", hook_name)
                sys.exit(1)
            with hook_path.open("r", encoding="utf-8", errors="replace") as handle:
                if marker not in handle.read():
                    logger.error("An existing %s hook cannot be replaced.", hook_name)
                    sys.exit(1)
        with hook_path.open("w", encoding="utf-8") as handle:
            handle.write(hook_contents)
        os.chmod(hook_path, 0o755)
        print(f"Installed {hook_name} hook at {hook_path}")
    except OSError:
        logger.error("Failed to install Git hook.")
        sys.exit(1)


def uninstall_git_hook(repo_root: str) -> None:
    """Remove the Git pre-commit hook if present.

    Args:
        repo_root: Root path of the Git repository.
    """
    _uninstall_git_hook(repo_root, "pre-commit", HOOK_MARKER)


def uninstall_git_pre_push_hook(repo_root: str) -> None:
    """Remove the Secret Sentinel-managed Git pre-push hook if present."""
    _uninstall_git_hook(repo_root, "pre-push", PRE_PUSH_HOOK_MARKER)


def _uninstall_git_hook(repo_root: str, hook_name: str, marker: str) -> None:
    """Remove a managed Git hook without disturbing unmanaged hooks."""
    try:
        hook_path = _get_git_hook_path(repo_root, hook_name)
        if os.path.lexists(hook_path):
            if hook_path.is_symlink():
                logger.error(
                    "The existing %s hook is not managed by Secret Sentinel.",
                    hook_name,
                )
                sys.exit(1)
            with hook_path.open("r", encoding="utf-8", errors="replace") as handle:
                if marker not in handle.read():
                    logger.error(
                        "The existing %s hook is not managed by Secret Sentinel.",
                        hook_name,
                    )
                    sys.exit(1)
            os.remove(hook_path)
            print(f"Removed {hook_name} hook at {hook_path}")
        else:
            print(f"No {hook_name} hook found to remove.")
    except OSError:
        logger.error("Failed to uninstall Git hook.")
        sys.exit(1)


def _get_git_hook_path(repo_root: str, hook_name: str = "pre-commit") -> Path:
    """Return the repository's path for a Git hook."""
    result = subprocess.run(
        [
            "git",
            "-C",
            repo_root,
            "rev-parse",
            "--git-path",
            f"hooks/{hook_name}",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode == 0 and result.stdout.strip():
        hook_path = Path(result.stdout.strip())
        if not hook_path.is_absolute():
            hook_path = Path(repo_root) / hook_path
        return hook_path
    return Path(repo_root) / ".git" / "hooks" / hook_name


def run_doctor(repo_root: Optional[str]) -> int:
    """Report setup health without changing repository files or showing secrets."""
    print("Secret Sentinel doctor")
    if repo_root is None:
        print("[FAIL] Git repository: not found")
        print("Run this command from inside a Git repository.")
        return 1

    print("[ OK ] Git repository: found")
    try:
        config = SecretSentinelConfig.load(repo_root)
    except (OSError, configparser.Error, ValueError):
        print("[FAIL] Configuration: could not be loaded")
        print(
            "Review .secret-sentinel.ini and .secretignore for invalid settings, "
            "then run `secret-sentinel --doctor` again."
        )
        return 1

    config_path = Path(repo_root) / ".secret-sentinel.ini"
    config_status = "valid" if config_path.is_file() else "defaults active"
    print(f"[ OK ] Configuration: {config_status}")
    print(
        f"[INFO] Scan settings: fail on {config.fail_on.name}; "
        f"{len(config.ignore_globs)} ignored path patterns; "
        f"{len(config.custom_rules)} custom rules"
    )

    hook_path = _get_git_hook_path(repo_root)
    hook_needs_setup = False
    if hook_path.is_symlink():
        print("[WARN] Pre-commit hook: symbolic link present; left unchecked")
        print("Review the linked hook manually; Secret Sentinel will not replace it.")
    elif hook_path.is_file():
        try:
            with hook_path.open("r", encoding="utf-8", errors="replace") as handle:
                managed = HOOK_MARKER in handle.read()
        except OSError:
            print("[WARN] Pre-commit hook: could not be checked")
        else:
            if managed:
                print("[ OK ] Pre-commit hook: installed")
            else:
                print("[WARN] Pre-commit hook: another hook is present")
                print(
                    "Keep the existing hook; combine the scanner with it manually "
                    "if needed."
                )
    else:
        print("[WARN] Pre-commit hook: not installed (optional)")
        hook_needs_setup = True

    pre_push_path = _get_git_hook_path(repo_root, "pre-push")
    if pre_push_path.is_symlink():
        print("[WARN] Pre-push hook: symbolic link present; left unchecked")
        print("Review the linked hook manually; Secret Sentinel will not replace it.")
    elif pre_push_path.is_file():
        try:
            with pre_push_path.open(
                "r", encoding="utf-8", errors="replace"
            ) as handle:
                managed_pre_push = PRE_PUSH_HOOK_MARKER in handle.read()
        except OSError:
            print("[WARN] Pre-push hook: could not be checked")
        else:
            if managed_pre_push:
                print("[ OK ] Pre-push hook: installed")
            else:
                print("[WARN] Pre-push hook: another hook is present")
                print(
                    "Keep the existing hook; combine the scanner with it manually "
                    "if needed."
                )
    else:
        print("[INFO] Pre-push hook: not installed (optional)")

    baseline_path = Path(repo_root) / ScanBaseline.DEFAULT_PATH
    baseline_error = False
    baseline_exists = baseline_path.exists() or baseline_path.is_symlink()
    if baseline_exists and not baseline_path.is_file():
        print("[FAIL] Baseline: expected a regular file")
        print(
            "Move the existing path after reviewing it, then create a baseline "
            "with `secret-sentinel --update-baseline`."
        )
        baseline_error = True
    elif baseline_path.is_file():
        key = os.environ.get(ScanBaseline.KEY_ENVIRONMENT_VARIABLE, "")
        if len(key.encode("utf-8")) >= ScanBaseline.MINIMUM_KEY_LENGTH:
            try:
                baseline = ScanBaseline(repo_root)
                baseline.load()
            except (OSError, ValueError):
                print("[FAIL] Baseline: could not be validated")
                print(
                    "Check the baseline file format and configured key; "
                    "recreate it only after reviewing current findings."
                )
                baseline_error = True
            else:
                print("[ OK ] Baseline: format valid; key meets minimum length")
        else:
            print("[WARN] Baseline: present; key is missing or too short")
            print(
                f"Set {ScanBaseline.KEY_ENVIRONMENT_VARIABLE} to the same "
                "random key used to create the baseline."
            )
    else:
        print("[INFO] Baseline: not configured (optional)")
        if os.environ.get(ScanBaseline.KEY_ENVIRONMENT_VARIABLE):
            print(
                "[INFO] A baseline key is set, but no baseline file was found; "
                "baseline checks are not active."
            )

    if config.ai_enabled:
        validation = "enabled (cloud opt-in)" if config.ai_cloud_enabled else "enabled (local)"
    else:
        validation = "disabled (optional)"
    print(f"[INFO] AI validation: {validation}")
    if baseline_error:
        print("Doctor checks failed; resolve the baseline issue above.")
    else:
        print("Doctor checks passed.")
    if hook_needs_setup:
        print("Next: run `secret-sentinel --init` to add the optional pre-commit hook.")
    if not os.path.lexists(pre_push_path):
        print(
            "Optional: run `secret-sentinel --install-pre-push-hook` to scan "
            "commits before pushing."
        )
    return 1 if baseline_error else 0


def run_pre_push_scan(repo_root: Optional[str], updates: str) -> int:
    """Scan commits Git is about to push and block pushes with findings."""
    if repo_root is None:
        logger.error("Pre-push scanning must run inside a Git repository.")
        return 1
    try:
        config = SecretSentinelConfig.load(repo_root)
        issues = scan_git_push_updates(
            repo_root,
            updates,
            ignore_globs=config.ignore_globs,
            custom_rules=config.custom_rules,
        )
    except (OSError, configparser.Error, RuntimeError, ValueError):
        logger.error("Pre-push scan failed; commits were not pushed.")
        return 1

    report = format_text(issues, fail_on=config.fail_on)
    print(report)
    should_block = bool(
        issues
        and calculate_overall_severity(issues).value >= config.fail_on.value
    )
    try:
        ScanHistory(repo_root).record_scan(
            issues,
            scan_type="pre-push",
            status="blocked" if should_block else "completed",
        )
    except OSError:
        logger.error("Pre-push scan could not record history; commits were not pushed.")
        return 1
    return int(should_block)


def run_suppression_audit(
    repo_root: Optional[str],
    output_format: str = "text",
    output_path: Optional[str] = None,
) -> int:
    """Report undocumented, expired, or unused inline suppressions."""
    if repo_root is None:
        logger.error(
            "Run `secret-sentinel --audit-suppressions` inside a Git repository."
        )
        return 1

    try:
        config = SecretSentinelConfig.load(repo_root)
        suppressions = audit_suppressions_in_repo(
            repo_root,
            ignore_globs=config.ignore_globs,
            custom_rules=config.custom_rules,
        )
    except (OSError, configparser.Error, ValueError):
        logger.error("Suppression audit failed; repository files could not be checked.")
        return 1

    formatters = {
        "text": format_suppression_audit_text,
        "json": format_suppression_audit_json,
        "sarif": format_suppression_audit_sarif,
    }
    report = formatters[output_format](suppressions)
    if output_path:
        try:
            with open(output_path, "w", encoding="utf-8") as handle:
                handle.write(report + "\n")
        except OSError:
            logger.error("Failed to write suppression audit report.")
            return 1
    else:
        print(report)
    return int(
        any(suppression["statuses"] != ["active"] for suppression in suppressions)
    )


def run_setup(repo_root: Optional[str]) -> int:
    """Guide users through common setup choices without making implicit changes."""
    if repo_root is None:
        logger.error("Run `secret-sentinel --setup` from inside a Git repository.")
        return 1
    if not sys.stdin.isatty():
        logger.error(
            "Interactive setup requires a terminal. See `secret-sentinel --help`."
        )
        return 2

    print("Choose how you want to get started:")
    print("  1. Install a pre-commit hook")
    print("  2. Track existing findings with a baseline")
    print("  3. Add a GitHub Actions scan")
    print("  4. Show local scan commands")
    print("  5. Install a pre-push hook")
    try:
        choice = input("Select 1-5 [4]: ").strip() or "4"
    except EOFError:
        print("No changes were made.")
        return 0

    if choice == "1":
        return run_init(repo_root)
    if choice == "2":
        print("Review current findings before recording a baseline.")
        print(
            "Set SECRET_SENTINEL_BASELINE_KEY to the same random key in your "
            "local environment and trusted CI secrets."
        )
        print(
            'Generate a key with `python -c "import secrets; '
            'print(secrets.token_hex(32))"`; do not commit it.'
        )
        print("Then run `secret-sentinel --update-baseline .`.")
        print("Later scans can use `secret-sentinel --baseline .`.")
        print("The baseline stores keyed fingerprints, not secret values.")
        return 0
    if choice == "3":
        print("See the copyable GitHub Actions example in the project README:")
        print("https://github.com/tajamul-wani/secret-sentinel#github-actions")
        print(
            "For pull requests, scan changed lines with "
            "`secret-sentinel --diff origin/main`."
        )
        return 0
    if choice == "4":
        print("Scan the working tree with `secret-sentinel .`.")
        print("Scan staged changes with `secret-sentinel --staged`.")
        return 0
    if choice == "5":
        return run_init(repo_root, hook_name="pre-push")

    logger.error("Choose 1, 2, 3, 4, or 5. No changes were made.")
    return 2


def run_init(
    repo_root: Optional[str],
    assume_yes: bool = False,
    hook_name: str = "pre-commit",
) -> int:
    """Install a supported Git hook only after explicit user confirmation."""
    if repo_root is None:
        command = "--init" if hook_name == "pre-commit" else "--setup"
        logger.error("Run `secret-sentinel %s` inside a Git repository.", command)
        return 1

    try:
        SecretSentinelConfig.load(repo_root)
    except (OSError, configparser.Error, ValueError):
        logger.error("Configuration could not be loaded; no changes were made.")
        return 1

    marker = HOOK_MARKER if hook_name == "pre-commit" else PRE_PUSH_HOOK_MARKER
    installer = (
        install_git_hook if hook_name == "pre-commit" else install_git_pre_push_hook
    )
    hook_path = _get_git_hook_path(repo_root, hook_name)
    if hook_path.is_symlink():
        logger.error("An existing %s hook cannot be replaced.", hook_name)
        return 1
    if hook_path.is_file():
        try:
            with hook_path.open("r", encoding="utf-8", errors="replace") as handle:
                managed = marker in handle.read()
        except OSError:
            logger.error("The existing %s hook could not be checked.", hook_name)
            return 1
        if managed:
            print(
                f"Secret Sentinel's {hook_name} hook is already installed; "
                "no changes were made."
            )
            return 0
        logger.error("An existing %s hook cannot be replaced.", hook_name)
        return 1

    if not assume_yes:
        if not sys.stdin.isatty():
            if hook_name == "pre-commit":
                logger.error("Use --yes to confirm setup when running non-interactively.")
            else:
                logger.error("Hook setup requires a terminal for confirmation.")
            return 2
        try:
            answer = input(
                f"Install the Secret Sentinel {hook_name} hook? [y/N] "
            )
        except EOFError:
            print("No changes were made.")
            return 0
        if answer.strip().lower() not in ("y", "yes"):
            print("No changes were made.")
            return 0

    try:
        installer(repo_root)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 1

    if hook_name == "pre-commit":
        print("Setup complete: the hook scans staged changes before each commit.")
        print(
            "Next: run `secret-sentinel .` to scan the working tree, "
            "or `secret-sentinel --doctor` to check setup."
        )
        print("Baselines are optional; review existing findings before creating one.")
    else:
        print("Setup complete: the hook scans newly pushed commits before each push.")
        print("Run `secret-sentinel --doctor` to check hook setup.")
    return 0


def scan_paths(
    paths: List[str],
    no_ai: bool,
    staged: bool,
    debug: bool = False,
    custom_rules: Optional[List[CustomRule]] = None,
    diff_base: Optional[str] = None,
    coverage: Optional[ScanCoverage] = None,
) -> List[Dict[str, Any]]:
    """Execute secret scan across paths or staged changes, optionally applying AI validation.

    Args:
        paths: Target paths to scan.
        no_ai: Whether to skip AI validation.
        staged: Whether to scan git staged changes.
        debug: Whether debug mode is active.
        diff_base: Optional Git revision for scanning added lines only.

    Returns:
        List of verified issue findings.
    """
    repo_root = get_git_root() or os.getcwd()
    config = SecretSentinelConfig.load(repo_root)
    ignore_globs = config.ignore_globs

    if debug:
        logger.debug("repo_root=%s", repo_root)
        logger.debug("ignore_globs=%s", ignore_globs)
        logger.debug("ai_enabled=%s", config.ai_enabled)

    issues: List[Dict[str, Any]] = []
    active_custom_rules = config.custom_rules if custom_rules is None else custom_rules
    if diff_base is not None:
        issues = scan_git_diff(
            diff_base,
            repo_root,
            ignore_globs=ignore_globs,
            custom_rules=active_custom_rules,
        )
    elif staged or not paths:
        issues = scan_staged_files(
            ignore_globs=ignore_globs,
            repo_root=repo_root,
            custom_rules=active_custom_rules,
        )
    else:
        issues = scan_disk_paths(
            paths,
            ignore_globs=ignore_globs,
            repo_root=repo_root,
            custom_rules=active_custom_rules,
            coverage=coverage,
        )

    if no_ai or not config.ai_enabled or not issues:
        return issues

    issues_by_source: Dict[str, List[Dict[str, Any]]] = {}
    for issue in issues:
        issues_by_source.setdefault(str(issue["source"]), []).append(issue)

    verified: List[Dict[str, Any]] = []
    for source_path, path_issues in issues_by_source.items():
        content: Optional[str] = None
        if staged or (not paths and diff_base is None):
            content = get_staged_content(source_path, repo_root)
        if content is None:
            disk_path = Path(repo_root) / source_path if not os.path.isabs(source_path) else Path(source_path)
            try:
                if disk_path.is_file():
                    with open(disk_path, "r", encoding="utf-8", errors="replace") as handle:
                        content = handle.read()
            except OSError:
                pass
        if content is None:
            verified.extend(path_issues)
            continue
        verified.extend(
            validate_issues(
                path_issues,
                source_path,
                content,
                allow_cloud=config.ai_cloud_enabled,
            )
        )

    return verified


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI entry point for Secret Sentinel.

    Args:
        argv: Optional command-line arguments.

    Returns:
        Exit code: 0 for success/no secrets, 1 when secrets are detected or on error.
    """
    args = parse_args(argv)
    setup_logging(debug=args.debug)
    git_root = get_git_root()
    repo_root = git_root or os.getcwd()

    if args.yes and not args.init:
        logger.error("--yes can only be used with --init.")
        return 2
    if args.coverage and (
        not args.paths
        or args.staged
        or args.git_history
        or args.diff is not None
        or args.commit_range is not None
        or args.all_refs
        or args.baseline
        or args.update_baseline
        or args.history
        or args.stats
        or args.clear_history
        or args.audit_suppressions
        or args.doctor
        or args.setup
        or args.init
        or args.yes
        or args.install_hook
        or args.uninstall_hook
        or args.install_pre_push_hook
        or args.uninstall_pre_push_hook
        or args.pre_push
    ):
        logger.error("--coverage requires an explicit on-disk path scan.")
        return 2

    if args.pre_push:
        if (
            args.paths
            or args.setup
            or args.doctor
            or args.audit_suppressions
            or args.init
            or args.yes
            or args.staged
            or args.git_history
            or args.diff is not None
            or args.commit_range is not None
            or args.all_refs
            or args.baseline
            or args.update_baseline
            or args.history
            or args.stats
            or args.clear_history
            or args.install_hook
            or args.uninstall_hook
            or args.install_pre_push_hook
            or args.uninstall_pre_push_hook
            or args.no_ai
            or args.fail_on is not None
            or args.history_limit != 10
            or args.output
            or args.format != "text"
        ):
            logger.error("--pre-push cannot be combined with other options.")
            return 2
        try:
            updates = sys.stdin.read()
        except OSError:
            logger.error("Could not read pre-push update data.")
            return 1
        return run_pre_push_scan(git_root, updates)

    if args.audit_suppressions:
        if (
            args.paths
            or args.setup
            or args.doctor
            or args.init
            or args.yes
            or args.staged
            or args.git_history
            or args.diff is not None
            or args.commit_range is not None
            or args.all_refs
            or args.baseline
            or args.update_baseline
            or args.history
            or args.stats
            or args.clear_history
            or args.install_hook
            or args.uninstall_hook
            or args.install_pre_push_hook
            or args.uninstall_pre_push_hook
            or args.no_ai
            or args.fail_on is not None
            or args.history_limit != 10
        ):
            logger.error(
                "--audit-suppressions cannot be combined with scan or management options."
            )
            return 2
        return run_suppression_audit(
            git_root, output_format=args.format, output_path=args.output
        )

    if args.setup:
        if (
            args.paths
            or args.doctor
            or args.init
            or args.yes
            or args.staged
            or args.git_history
            or args.diff is not None
            or args.commit_range is not None
            or args.all_refs
            or args.baseline
            or args.update_baseline
            or args.history
            or args.stats
            or args.clear_history
            or args.install_hook
            or args.uninstall_hook
            or args.install_pre_push_hook
            or args.uninstall_pre_push_hook
            or args.no_ai
            or args.fail_on is not None
            or args.history_limit != 10
            or args.output
            or args.format != "text"
        ):
            logger.error("--setup cannot be combined with scan or management options.")
            return 2
        return run_setup(git_root)

    if args.doctor:
        if (
            args.paths
            or args.setup
            or args.init
            or args.yes
            or args.staged
            or args.git_history
            or args.diff is not None
            or args.commit_range is not None
            or args.all_refs
            or args.baseline
            or args.update_baseline
            or args.history
            or args.stats
            or args.clear_history
            or args.install_hook
            or args.uninstall_hook
            or args.install_pre_push_hook
            or args.uninstall_pre_push_hook
            or args.no_ai
            or args.fail_on is not None
            or args.history_limit != 10
            or args.output
            or args.format != "text"
        ):
            logger.error("--doctor cannot be combined with scan or management options.")
            return 2
        return run_doctor(git_root)

    if args.init:
        if (
            args.paths
            or args.setup
            or args.staged
            or args.git_history
            or args.diff is not None
            or args.commit_range is not None
            or args.all_refs
            or args.baseline
            or args.update_baseline
            or args.history
            or args.stats
            or args.clear_history
            or args.install_hook
            or args.uninstall_hook
            or args.install_pre_push_hook
            or args.uninstall_pre_push_hook
            or args.no_ai
            or args.fail_on is not None
            or args.history_limit != 10
            or args.output
            or args.format != "text"
        ):
            logger.error("--init cannot be combined with scan or management options.")
            return 2
        return run_init(git_root, assume_yes=args.yes)

    if (args.baseline or args.update_baseline) and (
        args.history
        or args.stats
        or args.clear_history
        or args.install_hook
        or args.uninstall_hook
    ):
        logger.error("Baseline options can only be used with a scan.")
        return 2

    if args.history or args.stats or args.clear_history:
        if args.commit_range:
            logger.error("--commit-range cannot be combined with history options.")
            return 2
        history_manager = ScanHistory(repo_root)

        if args.clear_history:
            history_manager.clear_history()
            print("Scan history cleared.")
            return 0

        if args.history:
            history_records = history_manager.get_history(limit=args.history_limit)
            if not history_records:
                print("No scan history found.")
                return 0

            print("=" * 80)
            print("SCAN HISTORY (latest first)")
            print("=" * 80)
            for i, record in enumerate(history_records, 1):
                print(f"\n[{i}] {record['timestamp']}")
                print(f"    Type: {record['scan_type']}")
                print(f"    Status: {record['status']}")
                print(f"    Total issues: {record['total_issues']}")
                severity = record.get("severity_counts", {})
                if severity:
                    print("    Severity breakdown:")
                    for level, count in severity.items():
                        if count > 0:
                            print(f"      {level}: {count}")
            return 0

        if args.stats:
            stats = history_manager.get_statistics()
            if stats["total_scans"] == 0:
                print("No scan statistics available.")
                return 0

            print("=" * 80)
            print("SCAN STATISTICS")
            print("=" * 80)
            print(f"Total scans: {stats['total_scans']}")
            print(f"Total issues found: {stats['total_issues_found']}")
            print("\nSeverity summary:")
            for level, count in stats["severity_summary"].items():
                if count > 0:
                    print(f"  {level}: {count}")
            print("\nScans by type:")
            for scan_type, count in stats["scan_types"].items():
                print(f"  {scan_type}: {count}")

            if stats["latest_scan"]:
                latest = stats["latest_scan"]
                print(f"\nLatest scan: {latest['timestamp']}")
            return 0

    hook_actions = [
        args.install_hook,
        args.uninstall_hook,
        args.install_pre_push_hook,
        args.uninstall_pre_push_hook,
    ]
    if any(hook_actions):
        if (
            sum(hook_actions) != 1
            or args.paths
            or args.pre_push
            or args.setup
            or args.doctor
            or args.audit_suppressions
            or args.init
            or args.yes
            or args.staged
            or args.git_history
            or args.diff is not None
            or args.commit_range is not None
            or args.all_refs
            or args.baseline
            or args.update_baseline
            or args.history
            or args.stats
            or args.clear_history
            or args.no_ai
            or args.fail_on is not None
            or args.history_limit != 10
            or args.output
            or args.format != "text"
        ):
            logger.error("Git hook management cannot be combined with other options.")
            return 2
        if args.install_hook:
            install_git_hook(repo_root)
        elif args.uninstall_hook:
            uninstall_git_hook(repo_root)
        elif args.install_pre_push_hook:
            install_git_pre_push_hook(repo_root)
        else:
            uninstall_git_pre_push_hook(repo_root)
        return 0

    try:
        config = SecretSentinelConfig.load(repo_root)
    except (OSError, configparser.Error, ValueError) as exc:
        logger.error("Failed to load configuration: %s", exc)
        return 2
    threshold = SeverityLevel[args.fail_on.upper()] if args.fail_on else config.fail_on

    if args.git_history and (
        args.paths or args.staged or args.diff is not None or args.commit_range
    ):
        logger.error("--git-history cannot be combined with other scan modes.")
        return 2
    if args.diff is not None and (
        args.paths
        or args.staged
        or args.git_history
        or args.commit_range
        or args.all_refs
    ):
        logger.error("--diff cannot be combined with other scan modes.")
        return 2
    if args.commit_range and (
        args.paths or args.staged or args.git_history or args.diff is not None
    ):
        logger.error("--commit-range cannot be combined with other scan modes.")
        return 2
    if args.all_refs and not args.git_history:
        logger.error("--all-refs requires --git-history.")
        return 2
    if args.update_baseline and (args.output or args.format != "text"):
        logger.error("--update-baseline cannot be combined with --format or --output.")
        return 2

    coverage = ScanCoverage()
    if args.git_history:
        try:
            issues = scan_git_history(
                repo_root,
                ignore_globs=config.ignore_globs,
                all_refs=args.all_refs,
                custom_rules=config.custom_rules,
            )
        except (OSError, RuntimeError):
            logger.error("Git history scan failed.")
            return 1
    elif args.commit_range:
        try:
            issues = scan_git_commit_range(
                repo_root,
                args.commit_range[0],
                args.commit_range[1],
                ignore_globs=config.ignore_globs,
                custom_rules=config.custom_rules,
            )
        except (OSError, RuntimeError, ValueError):
            logger.error("Commit range scan failed.")
            return 1
    elif args.diff is not None:
        try:
            issues = scan_paths(
                [],
                args.no_ai,
                staged=False,
                debug=args.debug,
                custom_rules=config.custom_rules,
                diff_base=args.diff,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            logger.error("Diff scan failed: %s", exc)
            return 1
    else:
        try:
            issues = scan_paths(
                args.paths,
                args.no_ai,
                staged=args.staged,
                debug=args.debug,
                custom_rules=config.custom_rules,
                coverage=coverage,
            )
        except (OSError, configparser.Error, RuntimeError, ValueError):
            logger.error("Scan failed; requested files could not be checked.")
            return 1

    scan_incomplete = bool(coverage.unreadable_paths or coverage.missing_paths)
    if args.update_baseline:
        if scan_incomplete:
            logger.error(
                "Baseline not updated; the scan did not check every requested path."
            )
            return 1
        try:
            baseline = ScanBaseline(repo_root)
            baseline.save(issues)
        except (OSError, ValueError) as exc:
            logger.error("Failed to update baseline: %s", exc)
            return 1
        print(f"Baseline updated: {len(issues)} finding(s) recorded at {baseline.path}.")
        print("Secret values are not stored in the baseline.")
        return 0

    baseline_suppressed = 0
    if args.baseline:
        try:
            baseline = ScanBaseline(repo_root)
            issues, baseline_suppressed = baseline.filter_issues(issues)
        except FileNotFoundError:
            logger.error(
                "Baseline not found at %s. Run `secret-sentinel --update-baseline` first.",
                baseline.path,
            )
            return 1
        except (OSError, ValueError) as exc:
            logger.error("Failed to read baseline: %s", exc)
            return 1

    overall_severity = calculate_overall_severity(issues)
    should_block = bool(issues and (overall_severity.value >= threshold.value))

    history_manager = ScanHistory(repo_root)
    scan_type = (
        "git-history"
        if args.git_history
        else (
            "git-range"
            if args.commit_range
            else (
                "diff"
                if args.diff is not None
                else ("staged" if args.staged else "manual")
            )
        )
    )
    status = (
        "incomplete"
        if scan_incomplete
        else "blocked" if should_block else "completed"
    )
    history_manager.record_scan(issues, scan_type=scan_type, status=status)

    if args.format == "json":
        output_str = format_json(
            issues,
            fail_on=threshold,
            baseline_suppressed=baseline_suppressed,
            coverage=(
                coverage.as_dict()
                if args.coverage or scan_incomplete
                else None
            ),
        )
    elif args.format == "sarif":
        output_str = format_sarif(
            issues,
            repo_root=repo_root,
            baseline_suppressed=baseline_suppressed,
            coverage=(
                coverage.as_dict()
                if args.coverage or scan_incomplete
                else None
            ),
        )
    else:
        output_str = format_text(
            issues,
            fail_on=threshold,
            baseline_suppressed=baseline_suppressed,
            coverage=(
                coverage.as_dict()
                if args.coverage or scan_incomplete
                else None
            ),
        )

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as handle:
                handle.write(output_str + "\n")
        except OSError as exc:
            logger.error("Failed to write output file: %s", exc)
            return 1
    else:
        print(output_str)

    return 1 if should_block or scan_incomplete else 0


if __name__ == "__main__":
    sys.exit(main())
