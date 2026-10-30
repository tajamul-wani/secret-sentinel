"""Scanner engine for detecting secrets in files and git staged changes."""

import fnmatch
import os
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any

from .utils import is_text_bytes, sanitize_snippet, shannon_entropy
from .risk_scoring import get_risk_score

SECRET_PATTERNS = {
    "AWS Secret Access Key": re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|ANPA|AROA|AIPA|ANVA)[0-9A-Z]{16}\b"),
    "Google API Key": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    "Stripe API Key": re.compile(r"\bpk_(?:test|live)_[A-Za-z0-9]{24}\b"),
    "GitHub Token": re.compile(r"\bghp_[A-Za-z0-9_]{36}\b"),
    "Slack Token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "JWT": re.compile(r"\beyJ[0-9A-Za-z_\-]+\.[0-9A-Za-z_\-]+\.[0-9A-Za-z_\-]+\b"),
    "Twilio Secret Key": re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
    "Generic Secret Assignment": re.compile(
        r"(?i)\b(?:api[_\-]?key|secret|token|password|passwd|auth|credential|client_secret|private_key|oauth[_\-]?token)\b\s*[:=]\s*[\"']?([A-Za-z0-9_\-+\/=]{16,})[\"']?"
    ),
}
SECRET_STRING_PATTERN = re.compile(r"[\"']([A-Za-z0-9+/=_.-]{24,})[\"']")
ENTROPY_THRESHOLD = 4.6
MIN_ENTROPY_LENGTH = 24
DEFAULT_IGNORE = [
    "__pycache__/*",
    "*.py[cod]",
    "*.pyo",
    "*.pyd",
    ".git/*",
    "venv/*",
    ".venv/*",
    ".venv*/*",
    "env/*",
    ".env/*",
    ".secret-sentinel/*",
    "node_modules/*",
]


def _run_git_command(args: List[str], cwd: Optional[str] = None, text: bool = True) -> subprocess.CompletedProcess:
    """Execute a git command with subprocess.

    Args:
        args: Command-line arguments for git.
        cwd: Optional working directory.
        text: Whether to decode stdout/stderr as text.

    Returns:
        CompletedProcess instance containing return code and output.
    """
    return subprocess.run(
        ["git"] + args,
        cwd=cwd,
        capture_output=True,
        text=text,
        check=False,
    )


def get_git_root() -> Optional[str]:
    """Retrieve the top-level directory of the current Git repository.

    Returns:
        Absolute path to git root if inside a repository, or None.
    """
    result = _run_git_command(["rev-parse", "--show-toplevel"])
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def get_staged_paths() -> List[str]:
    """List file paths currently staged in Git index (Added, Copied, Modified).

    Returns:
        List of relative paths to staged files.
    """
    result = _run_git_command(["diff", "--cached", "--name-only", "--diff-filter=ACM"])
    if result.returncode != 0:
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def get_staged_content(path: str) -> Optional[str]:
    """Fetch text content of a staged file from the Git index.

    Args:
        path: Path of the file in the Git index.

    Returns:
        Text content if file is plain text, or None if binary or unreadable.
    """
    result = _run_git_command(["show", f":{path}"], text=False)
    if result.returncode != 0:
        return None
    data = result.stdout if isinstance(result.stdout, str) else result.stdout
    if isinstance(data, bytes):
        if not is_text_bytes(data):
            return None
        return data.decode("utf-8", errors="replace")
    return data


def _normalize_path(path: str) -> str:
    """Normalize path separators to forward slashes.

    Args:
        path: Path string.

    Returns:
        Normalized path string.
    """
    return path.replace("\\", "/")


def _sanitize_source_path(path: str, repo_root: Optional[str] = None) -> str:
    """Convert absolute paths to repo-relative paths to avoid leaking system paths.

    Args:
        path: File path to sanitize.
        repo_root: Optional repository root path.

    Returns:
        Clean, relative path where possible.
    """
    if repo_root:
        try:
            rel = os.path.relpath(path, repo_root)
            if not rel.startswith(".."):
                return _normalize_path(rel)
        except ValueError:
            pass
    return _normalize_path(path)


def _is_ignored(path: str, ignore_globs: List[str], repo_root: Optional[str] = None) -> bool:
    """Check whether a path matches any pattern in ignore_globs.

    Args:
        path: Target file or directory path.
        ignore_globs: List of glob patterns.
        repo_root: Optional repository root for relative matching.

    Returns:
        True if the path should be ignored, False otherwise.
    """
    normalized_path = _normalize_path(path)
    rel_path = normalized_path
    if repo_root:
        try:
            rel_path = _normalize_path(os.path.relpath(path, repo_root))
        except ValueError:
            rel_path = normalized_path
    for pattern in ignore_globs:
        normalized_pattern = _normalize_path(pattern)
        if fnmatch.fnmatch(rel_path, normalized_pattern) or fnmatch.fnmatch(normalized_path, normalized_pattern):
            return True
    return False


def _line_has_secret_keyword(line: str) -> bool:
    """Check whether a line contains keywords typically associated with secrets.

    Args:
        line: Text line to inspect.

    Returns:
        True if a secret keyword is found.
    """
    return bool(
        re.search(
            r"(?i)(?:^|[\W_])(secret|token|api[_\-]?key|password|passwd|auth|credential|client_secret|private_key|oauth[_\-]?token)(?:[\W_]|$)",
            line,
        )
    )


def scan_text(content: str, source: str) -> List[Dict[str, Any]]:
    """Scan string content for known secret patterns and high-entropy strings.

    Args:
        content: The text content to analyze.
        source: Source identifier (e.g. file path).

    Returns:
        List of issue dictionaries describing each finding.
    """
    issues = []
    lines = content.splitlines()
    for lineno, line in enumerate(lines, start=1):
        for name, pattern in SECRET_PATTERNS.items():
            for match in pattern.finditer(line):
                value = match.group(1) if match.groups() else match.group(0)
                severity = get_risk_score(name)
                issues.append(
                    {
                        "source": source,
                        "line": lineno,
                        "matcher": name,
                        "value": value,
                        "snippet": line.strip(),
                        "confidence": "high",
                        "reason": "pattern",
                        "severity": severity.name,
                    }
                )
        for match in SECRET_STRING_PATTERN.finditer(line):
            value = match.group(1)
            if len(value) < MIN_ENTROPY_LENGTH:
                continue
            if not _line_has_secret_keyword(line):
                continue
            entropy = shannon_entropy(value)
            if entropy >= ENTROPY_THRESHOLD:
                severity = get_risk_score("High entropy string")
                issues.append(
                    {
                        "source": source,
                        "line": lineno,
                        "matcher": "High entropy string",
                        "value": value,
                        "snippet": line.strip(),
                        "confidence": "medium",
                        "reason": "entropy",
                        "entropy": round(entropy, 2),
                        "severity": severity.name,
                    }
                )
    return issues


def scan_staged_files(
    ignore_globs: Optional[List[str]] = None, repo_root: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Scan all files currently staged in Git index.

    Args:
        ignore_globs: Optional list of glob patterns to exclude.
        repo_root: Optional repository root path.

    Returns:
        List of issue findings across all staged files.
    """
    issues = []
    active_ignores = ignore_globs or DEFAULT_IGNORE
    for path in get_staged_paths():
        absolute_path = os.path.join(repo_root or os.getcwd(), path)
        if _is_ignored(absolute_path, active_ignores, repo_root):
            continue
        content = get_staged_content(path)
        if content is None:
            continue
        safe_path = _sanitize_source_path(path, repo_root)
        issues.extend(scan_text(content, safe_path))
    return issues


def scan_paths(
    paths: List[str],
    ignore_globs: Optional[List[str]] = None,
    repo_root: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Scan specified file and directory paths on disk.

    Args:
        paths: List of directory or file paths to scan.
        ignore_globs: Optional list of glob patterns to exclude.
        repo_root: Optional repository root path for relative resolution.

    Returns:
        List of issue findings.
    """
    issues = []
    active_ignores = ignore_globs or DEFAULT_IGNORE
    for path in paths:
        if os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                if _is_ignored(root, active_ignores, repo_root):
                    dirs[:] = []
                    continue
                if ".git" in root.split(os.sep):
                    dirs[:] = []
                    continue
                for file_name in files:
                    full_path = os.path.join(root, file_name)
                    if _is_ignored(full_path, active_ignores, repo_root):
                        continue
                    try:
                        with open(full_path, "rb") as handle:
                            data = handle.read(2048)
                            if not is_text_bytes(data):
                                continue
                        with open(full_path, "r", encoding="utf-8", errors="replace") as handle:
                            content = handle.read()
                    except OSError:
                        continue
                    safe_source = _sanitize_source_path(full_path, repo_root)
                    issues.extend(scan_text(content, safe_source))
            continue
        if not os.path.isfile(path):
            continue
        if _is_ignored(path, active_ignores, repo_root):
            continue
        try:
            with open(path, "rb") as handle:
                data = handle.read(2048)
                if not is_text_bytes(data):
                    continue
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                content = handle.read()
        except OSError:
            continue
        safe_source = _sanitize_source_path(path, repo_root)
        issues.extend(scan_text(content, safe_source))
    return issues


def summarize_issues(issues: List[Dict[str, Any]]) -> str:
    """Generate a sanitized, human-readable summary of detected issues.

    Secret values in snippets are sanitized and redacted to prevent leaking
    credentials in terminal output or logs.

    Args:
        issues: List of issue dictionaries.

    Returns:
        Formatted summary string.
    """
    if not issues:
        return ""
    lines = [f"Detected potential secrets ({len(issues)}):"]
    for issue in issues:
        raw_snippet = str(issue.get("snippet", ""))
        secret_val = str(issue.get("value", ""))
        safe_snippet = sanitize_snippet(raw_snippet, secret_val)
        entry = f"{issue['source']}:{issue['line']} [{issue['matcher']}] - {safe_snippet}"
        if issue.get("entropy") is not None:
            entry += f" (entropy={issue['entropy']})"
        lines.append(entry)
    return "\n".join(lines)
