import argparse
import os
import sys
from pathlib import Path
from typing import List, Dict, Optional

from .config import SecretSentinelConfig
from .scanner import (
    scan_paths as scan_disk_paths,
    scan_staged_files,
    get_git_root,
    get_staged_content,
    get_staged_paths,
    summarize_issues,
)
from .ai_validator import validate_issues


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="secret-sentinel",
        description="Local AI-assisted secret scanner for Git pre-commit hooks.",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="Paths to scan. If omitted and --staged is not set, scans staged files in the current Git repo.",
    )
    parser.add_argument(
        "--staged",
        action="store_true",
        help="Scan staged Git files instead of disk paths.",
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
        "--version",
        action="version",
        version="secret-sentinel 0.1.0",
    )
    return parser.parse_args()


def install_git_hook(repo_root: str) -> None:
    try:
        hook_dir = os.path.join(repo_root, ".git", "hooks")
        if not os.path.isdir(hook_dir):
            raise FileNotFoundError("No .git/hooks directory found in repository root.")
        hook_path = os.path.join(hook_dir, "pre-commit")
        hook_contents = """#!/usr/bin/env python3
import os
import sys
from pathlib import Path

repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))

from secret_sentinel.cli import main

if __name__ == '__main__':
    sys.exit(main(["--no-ai", "--staged"]))
"""
        with open(hook_path, "w", encoding="utf-8") as handle:
            handle.write(hook_contents)
        os.chmod(hook_path, 0o755)
        print(f"Installed pre-commit hook at {hook_path}")
    except Exception as exc:
        print(f"Failed to install Git hook: {exc}", file=sys.stderr)
        sys.exit(1)


def uninstall_git_hook(repo_root: str) -> None:
    try:
        hook_path = os.path.join(repo_root, ".git", "hooks", "pre-commit")
        if os.path.exists(hook_path):
            os.remove(hook_path)
            print(f"Removed pre-commit hook at {hook_path}")
        else:
            print("No pre-commit hook found to remove.")
    except Exception as exc:
        print(f"Failed to remove Git hook: {exc}", file=sys.stderr)
        sys.exit(1)


def scan_paths(paths: List[str], no_ai: bool, staged: bool, debug: bool = False) -> List[Dict[str, object]]:
    repo_root = get_git_root() or os.getcwd()
    config = SecretSentinelConfig.load(repo_root)
    ignore_globs = config.ignore_globs
    if debug:
        print(f"repo_root={repo_root}")
        print(f"ignore_globs={ignore_globs}")
        print(f"ai_enabled={config.ai_enabled}")
    issues = []
    if staged or not paths:
        issues = scan_staged_files(ignore_globs=ignore_globs, repo_root=repo_root)
    else:
        issues = scan_disk_paths(paths, ignore_globs=ignore_globs, repo_root=repo_root)
    if no_ai or not config.ai_enabled:
        return issues
    verified = []
    for path in paths if paths else get_staged_paths():
        content = None
        if not paths:
            content = get_staged_content(path)
        if content is None:
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as handle:
                    content = handle.read()
            except OSError:
                continue
        if content is None:
            continue
        path_issues = [issue for issue in issues if issue["source"] == path]
        verified.extend(validate_issues(path_issues, path, content))
    return verified


def main(argv=None) -> int:
    args = parse_args() if argv is None else parse_args_from(argv)
    repo_root = get_git_root() or os.getcwd()
    if args.install_hook:
        install_git_hook(repo_root)
        return 0
    if args.uninstall_hook:
        uninstall_git_hook(repo_root)
        return 0
    issues = scan_paths(args.paths, args.no_ai, staged=args.staged, debug=args.debug)
    if issues:
        print(summarize_issues(issues))
        print("Commit blocked: secret-sentinel detected potential hardcoded secrets.")
        return 1
    print("secret-sentinel scan passed.")
    return 0


def parse_args_from(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="secret-sentinel",
        description="Local AI-assisted secret scanner for Git pre-commit hooks.",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="Paths to scan. If omitted and --staged is not set, scans staged files in the current Git repo.",
    )
    parser.add_argument(
        "--staged",
        action="store_true",
        help="Scan staged Git files instead of disk paths.",
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
        "--version",
        action="version",
        version="secret-sentinel 0.1.0",
    )
    return parser.parse_args(argv)
