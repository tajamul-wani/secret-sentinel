"""Scanner engine for detecting secrets in files and git staged changes."""

import fnmatch
import os
import re
import subprocess
from datetime import date
from pathlib import Path
from typing import Dict, List, Optional, Any

from .config import CustomRule
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
    "Private Key": re.compile(r"-----BEGIN (?:[A-Z0-9_-]+\s)?PRIVATE KEY-----"),
    "Database Connection URI": re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp[s]?):\/\/[^\s:]+:([^\s@]+)@[^\s/:]+"),
    "OpenAI API Key": re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}\b"),
    "Anthropic API Key": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{32,}\b"),
    "HuggingFace Token": re.compile(r"\bhf_[A-Za-z0-9]{34}\b"),
    "PyPI API Token": re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b"),
    "NPM Access Token": re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
    "Generic Secret Assignment": re.compile(
        r"(?i)\b(?:api[_\-]?key|secret|token|password|passwd|auth|credential|client_secret|private_key|oauth[_\-]?token)\b\s*[:=]\s*[\"']?([A-Za-z0-9_\-+\/=]{16,})[\"']?"
    ),
}
SUPPRESSION_DIRECTIVE_PATTERN = re.compile(
    r"(?i)(?:#|//|/\*)\s*secret[-_]?sentinel:\s*"
    r"(?P<action>disable[-_]next[-_]line|ignore)\b(?P<metadata>.*?)(?:\*/)?\s*$"
)
SUPPRESSION_EXPIRY_PATTERN = re.compile(r"(?i)\bexpires?\s*[:=]\s*([^\s;,*/]+)")
SECRET_STRING_PATTERN = re.compile(r"[\"']([A-Za-z0-9+/=_.-]{24,})[\"']")
DIFF_HUNK_PATTERN = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
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


def _suppression_is_active(metadata: str) -> bool:
    """Return whether a suppression directive has not expired."""
    expiry_match = SUPPRESSION_EXPIRY_PATTERN.search(metadata)
    if not expiry_match:
        return True

    expiry_text = expiry_match.group(1)
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", expiry_text):
        return False
    try:
        expiry = date.fromisoformat(expiry_text)
    except ValueError:
        return False
    return date.today() <= expiry


def scan_text(
    content: str,
    source: str,
    custom_rules: Optional[List[CustomRule]] = None,
) -> List[Dict[str, Any]]:
    """Scan string content for known secret patterns and high-entropy strings.

    Supports inline and next-line suppressions, optionally with an expiry date.

    Args:
        content: The text content to analyze.
        source: Source identifier (e.g. file path).
        custom_rules: Optional configured regular-expression rules.

    Returns:
        List of issue dictionaries describing each finding.
    """
    issues = []
    lines = content.splitlines()
    skip_next_line = False

    for lineno, line in enumerate(lines, start=1):
        if skip_next_line:
            skip_next_line = False
            continue

        directive = SUPPRESSION_DIRECTIVE_PATTERN.search(line)
        if directive and _suppression_is_active(directive.group("metadata")):
            if directive.group("action").lower().startswith("disable"):
                skip_next_line = True
            else:
                continue
            continue

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
        for rule in custom_rules or []:
            for match in rule.pattern.finditer(line):
                issues.append(
                    {
                        "source": source,
                        "line": lineno,
                        "matcher": rule.name,
                        "value": match.group(0),
                        "snippet": line.strip(),
                        "confidence": "high",
                        "reason": "custom-pattern",
                        "severity": rule.severity.name,
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
    ignore_globs: Optional[List[str]] = None,
    repo_root: Optional[str] = None,
    custom_rules: Optional[List[CustomRule]] = None,
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
        issues.extend(scan_text(content, safe_path, custom_rules=custom_rules))
    return issues


def scan_git_history(
    repo_root: str,
    ignore_globs: Optional[List[str]] = None,
    all_refs: bool = False,
    custom_rules: Optional[List[CustomRule]] = None,
) -> List[Dict[str, Any]]:
    """Scan text blobs reachable from HEAD or all refs and report each finding once.

    Findings are attributed to the earliest commit in which their path and
    detected value appear. When all_refs is false, refs not reachable from HEAD
    are not scanned.
    """
    revisions = ["--all"] if all_refs else ["HEAD"]
    commits_result = _run_git_command(
        ["rev-list", "--reverse", *revisions], cwd=repo_root
    )
    if commits_result.returncode != 0:
        raise RuntimeError("Unable to read repository history for scanning.")

    active_ignores = ignore_globs or DEFAULT_IGNORE
    last_blob_by_path: Dict[str, str] = {}
    seen_findings: set[tuple[str, str, str]] = set()
    issues: List[Dict[str, Any]] = []

    for commit in commits_result.stdout.splitlines():
        tree_result = _run_git_command(
            ["ls-tree", "-r", "-z", "--full-tree", commit],
            cwd=repo_root,
            text=False,
        )
        if tree_result.returncode != 0:
            raise RuntimeError("Unable to read repository history for scanning.")

        for entry in tree_result.stdout.split(b"\0"):
            if not entry:
                continue
            metadata, raw_path = entry.split(b"\t", 1)
            _mode, object_type, blob_oid = metadata.decode("ascii").split()
            if object_type != "blob":
                continue

            path = os.fsdecode(raw_path)
            absolute_path = os.path.join(repo_root, path)
            if _is_ignored(absolute_path, active_ignores, repo_root):
                continue
            if last_blob_by_path.get(path) == blob_oid:
                continue
            last_blob_by_path[path] = blob_oid

            blob_result = _run_git_command(
                ["cat-file", "blob", blob_oid],
                cwd=repo_root,
                text=False,
            )
            if blob_result.returncode != 0:
                raise RuntimeError("Unable to read repository history for scanning.")
            if not is_text_bytes(blob_result.stdout):
                continue

            source = _sanitize_source_path(absolute_path, repo_root)
            content = blob_result.stdout.decode("utf-8", errors="replace")
            for issue in scan_text(content, source, custom_rules=custom_rules):
                finding_key = (source, issue["matcher"], issue["value"])
                if finding_key in seen_findings:
                    continue
                seen_findings.add(finding_key)
                issue["commit"] = commit
                issues.append(issue)

    return issues


def scan_git_diff(
    base: str,
    repo_root: str,
    ignore_globs: Optional[List[str]] = None,
    custom_rules: Optional[List[CustomRule]] = None,
) -> List[Dict[str, Any]]:
    """Scan only added lines in the working tree diff against a Git commit."""
    if not base or base.startswith("-"):
        raise ValueError("A valid base commit or ref is required for diff scanning.")

    base_result = _run_git_command(
        ["rev-parse", "--verify", "--quiet", "--end-of-options", f"{base}^{{commit}}"],
        cwd=repo_root,
    )
    if base_result.returncode != 0:
        raise ValueError(f"Unable to resolve diff base {base!r} to a commit.")
    base_commit = base_result.stdout.strip()

    paths_result = _run_git_command(
        ["diff", "--name-only", "-z", "--diff-filter=ACMRT", base_commit, "--"],
        cwd=repo_root,
        text=False,
    )
    if paths_result.returncode != 0:
        raise RuntimeError("Unable to list changed files for diff scanning.")

    active_ignores = ignore_globs or DEFAULT_IGNORE
    issues: List[Dict[str, Any]] = []
    for raw_path in paths_result.stdout.split(b"\0"):
        if not raw_path:
            continue
        path = os.fsdecode(raw_path)
        absolute_path = os.path.join(repo_root, path)
        if _is_ignored(absolute_path, active_ignores, repo_root):
            continue
        if not os.path.isfile(absolute_path):
            continue

        try:
            with open(absolute_path, "rb") as handle:
                data = handle.read()
        except OSError:
            continue
        if not is_text_bytes(data[:2048]):
            continue

        patch_result = _run_git_command(
            [
                "diff",
                "--unified=0",
                "--no-color",
                "--no-ext-diff",
                base_commit,
                "--",
                path,
            ],
            cwd=repo_root,
            text=False,
        )
        if patch_result.returncode != 0:
            raise RuntimeError("Unable to read changed lines for diff scanning.")

        added_lines: set[int] = set()
        patch_text = patch_result.stdout.decode("utf-8", errors="replace")
        for line in patch_text.splitlines():
            hunk = DIFF_HUNK_PATTERN.match(line)
            if not hunk:
                continue
            start = int(hunk.group(1))
            count = int(hunk.group(2) or 1)
            added_lines.update(range(start, start + count))
        if not added_lines:
            continue

        source = _sanitize_source_path(absolute_path, repo_root)
        content = data.decode("utf-8", errors="replace")
        issues.extend(
            issue
            for issue in scan_text(content, source, custom_rules=custom_rules)
            if issue["line"] in added_lines
        )
    return issues


def scan_paths(
    paths: List[str],
    ignore_globs: Optional[List[str]] = None,
    repo_root: Optional[str] = None,
    custom_rules: Optional[List[CustomRule]] = None,
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
                    issues.extend(scan_text(content, safe_source, custom_rules=custom_rules))
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
        issues.extend(scan_text(content, safe_source, custom_rules=custom_rules))
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
