import argparse
import os
import sys
from typing import List, Dict

from .scanner import (
    scan_paths as scan_disk_paths,
    scan_staged_files,
    get_staged_paths,
    get_staged_content,
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
        help="Paths to scan. If omitted, scans staged files in the current Git repo.",
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
        "--version",
        action="version",
        version="secret-sentinel 0.1.0",
    )
    return parser.parse_args()


def install_git_hook() -> None:
    try:
        repo_root = os.path.abspath(os.getcwd())
        hook_dir = os.path.join(repo_root, ".git", "hooks")
        if not os.path.isdir(hook_dir):
            raise FileNotFoundError("No .git/hooks directory found in current directory.")
        hook_path = os.path.join(hook_dir, "pre-commit")
        hook_contents = """#!/usr/bin/env python3
import os
import sys
from pathlib import Path

repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))

from secret_sentinel.cli import main

if __name__ == '__main__':
    sys.exit(main(["--no-ai"]))
"""
        with open(hook_path, "w", encoding="utf-8") as handle:
            handle.write(hook_contents)
        os.chmod(hook_path, 0o755)
        print(f"Installed pre-commit hook at {hook_path}")
    except Exception as exc:
        print(f"Failed to install Git hook: {exc}", file=sys.stderr)
        sys.exit(1)


def scan_paths(paths: List[str], no_ai: bool) -> List[Dict[str, object]]:
    issues = []
    if not paths:
        issues = scan_staged_files()
    else:
        issues = []
        for path in paths:
            issues.extend(scan_disk_paths([path]))
    if no_ai:
        return issues
    verified = []
    for path in paths or get_staged_paths():
        content = get_staged_content(path) if not paths else None
        if content is None and path:
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
    if args.install_hook:
        install_git_hook()
        return 0
    issues = scan_paths(args.paths, args.no_ai)
    if issues:
        print(summarize_issues(issues))
        print(
            "Commit blocked: secret-sentinel detected potential hardcoded secrets."
        )
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
        help="Paths to scan. If omitted, scans staged files in the current Git repo.",
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
        "--version",
        action="version",
        version="secret-sentinel 0.1.0",
    )
    return parser.parse_args(argv)
