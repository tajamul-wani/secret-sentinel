"""Command-line interface for Secret Sentinel."""

import argparse
import configparser
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from .ai_validator import validate_issues
from .baseline import ScanBaseline
from .config import CustomRule, SecretSentinelConfig
from .formatters import format_json, format_sarif, format_text
from .history import ScanHistory
from .risk_scoring import SeverityLevel, calculate_overall_severity
from .scanner import (
    get_git_root,
    get_staged_content,
    get_staged_paths,
    scan_paths as scan_disk_paths,
    scan_git_history,
    scan_staged_files,
    summarize_issues,
)

logger = logging.getLogger("secret_sentinel")
HOOK_MARKER = "# secret-sentinel managed hook"


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
        description="Local AI-assisted secret scanner for Git pre-commit hooks.",
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
        version="secret-sentinel 0.1.0",
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
    try:
        hook_dir = os.path.join(repo_root, ".git", "hooks")
        if not os.path.isdir(hook_dir):
            logger.error("No Git hooks directory found in repository.")
            sys.exit(1)
        hook_path = os.path.join(hook_dir, "pre-commit")
        if os.path.lexists(hook_path):
            if os.path.islink(hook_path):
                logger.error("An existing pre-commit hook cannot be replaced.")
                sys.exit(1)
            with open(hook_path, "r", encoding="utf-8", errors="replace") as handle:
                if HOOK_MARKER not in handle.read():
                    logger.error("An existing pre-commit hook cannot be replaced.")
                    sys.exit(1)
        hook_contents = """#!/usr/bin/env python3
import sys
from pathlib import Path

""" + HOOK_MARKER + """
# Resolve repository root from .git/hooks/pre-commit
repo_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(repo_root))

from secret_sentinel.cli import main

if __name__ == "__main__":
    sys.exit(main(["--no-ai", "--staged"]))
"""
        with open(hook_path, "w", encoding="utf-8") as handle:
            handle.write(hook_contents)
        os.chmod(hook_path, 0o755)
        print(f"Installed pre-commit hook at {hook_path}")
    except OSError:
        logger.error("Failed to install Git hook.")
        sys.exit(1)


def uninstall_git_hook(repo_root: str) -> None:
    """Remove the Git pre-commit hook if present.

    Args:
        repo_root: Root path of the Git repository.
    """
    try:
        hook_path = os.path.join(repo_root, ".git", "hooks", "pre-commit")
        if os.path.lexists(hook_path):
            if os.path.islink(hook_path):
                logger.error("The existing pre-commit hook is not managed by Secret Sentinel.")
                sys.exit(1)
            with open(hook_path, "r", encoding="utf-8", errors="replace") as handle:
                if HOOK_MARKER not in handle.read():
                    logger.error("The existing pre-commit hook is not managed by Secret Sentinel.")
                    sys.exit(1)
            os.remove(hook_path)
            print(f"Removed pre-commit hook at {hook_path}")
        else:
            print("No pre-commit hook found to remove.")
    except OSError:
        logger.error("Failed to uninstall Git hook.")
        sys.exit(1)


def scan_paths(
    paths: List[str],
    no_ai: bool,
    staged: bool,
    debug: bool = False,
    custom_rules: Optional[List[CustomRule]] = None,
) -> List[Dict[str, Any]]:
    """Execute secret scan across paths or staged changes, optionally applying AI validation.

    Args:
        paths: Target paths to scan.
        no_ai: Whether to skip AI validation.
        staged: Whether to scan git staged changes.
        debug: Whether debug mode is active.

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
    if staged or not paths:
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
        )

    if no_ai or not config.ai_enabled or not issues:
        return issues

    issues_by_source: Dict[str, List[Dict[str, Any]]] = {}
    for issue in issues:
        issues_by_source.setdefault(str(issue["source"]), []).append(issue)

    verified: List[Dict[str, Any]] = []
    for source_path, path_issues in issues_by_source.items():
        content: Optional[str] = None
        if staged or not paths:
            content = get_staged_content(source_path)
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
    repo_root = get_git_root() or os.getcwd()

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

    if args.install_hook:
        install_git_hook(repo_root)
        return 0
    if args.uninstall_hook:
        uninstall_git_hook(repo_root)
        return 0

    try:
        config = SecretSentinelConfig.load(repo_root)
    except (OSError, configparser.Error, ValueError) as exc:
        logger.error("Failed to load configuration: %s", exc)
        return 2
    threshold = SeverityLevel[args.fail_on.upper()] if args.fail_on else config.fail_on

    if args.git_history and (args.paths or args.staged):
        logger.error("--git-history cannot be combined with paths or --staged.")
        return 2
    if args.all_refs and not args.git_history:
        logger.error("--all-refs requires --git-history.")
        return 2
    if args.update_baseline and (args.output or args.format != "text"):
        logger.error("--update-baseline cannot be combined with --format or --output.")
        return 2

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
    else:
        issues = scan_paths(
            args.paths,
            args.no_ai,
            staged=args.staged,
            debug=args.debug,
            custom_rules=config.custom_rules,
        )

    if args.update_baseline:
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
    scan_type = "git-history" if args.git_history else ("staged" if args.staged else "manual")
    status = "blocked" if should_block else "completed"
    history_manager.record_scan(issues, scan_type=scan_type, status=status)

    if args.format == "json":
        output_str = format_json(
            issues, fail_on=threshold, baseline_suppressed=baseline_suppressed
        )
    elif args.format == "sarif":
        output_str = format_sarif(
            issues, repo_root=repo_root, baseline_suppressed=baseline_suppressed
        )
    else:
        output_str = format_text(
            issues, fail_on=threshold, baseline_suppressed=baseline_suppressed
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

    return 1 if should_block else 0


if __name__ == "__main__":
    sys.exit(main())
