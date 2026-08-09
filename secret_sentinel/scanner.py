import fnmatch
import os
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

from .utils import is_text_bytes, shannon_entropy

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
    "node_modules/*",
]


def _run_git_command(args: List[str], cwd: Optional[str] = None, text: bool = True):
    result = subprocess.run(
        ["git"] + args,
        cwd=cwd,
        capture_output=True,
        text=text,
        check=False,
    )
    return result


def get_git_root() -> Optional[str]:
    result = _run_git_command(["rev-parse", "--show-toplevel"])
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def get_staged_paths() -> List[str]:
    result = _run_git_command(["diff", "--cached", "--name-only", "--diff-filter=ACM"])
    if result.returncode != 0:
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def get_staged_content(path: str) -> Optional[str]:
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
    return path.replace(os.sep, "/")


def _is_ignored(path: str, ignore_globs: List[str], repo_root: Optional[str] = None) -> bool:
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
    return bool(re.search(r"(?i)\b(secret|token|api[_\-]?key|password|passwd|auth|credential|client_secret|private_key|oauth[_\-]?token)\b", line))


def scan_text(content: str, source: str) -> List[Dict[str, object]]:
    issues = []
    lines = content.splitlines()
    for lineno, line in enumerate(lines, start=1):
        for name, pattern in SECRET_PATTERNS.items():
            for match in pattern.finditer(line):
                value = match.group(1) if match.groups() else match.group(0)
                issues.append(
                    {
                        "source": source,
                        "line": lineno,
                        "matcher": name,
                        "value": value,
                        "snippet": line.strip(),
                        "confidence": "high",
                        "reason": "pattern",
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
                    }
                )
    return issues


def scan_staged_files(ignore_globs: List[str] = None, repo_root: Optional[str] = None) -> List[Dict[str, object]]:
    issues = []
    ignore_globs = ignore_globs or DEFAULT_IGNORE
    for path in get_staged_paths():
        absolute_path = os.path.join(repo_root or os.getcwd(), path)
        if _is_ignored(absolute_path, ignore_globs, repo_root):
            continue
        content = get_staged_content(path)
        if content is None:
            continue
        issues.extend(scan_text(content, path))
    return issues


def scan_paths(paths: List[str], ignore_globs: List[str] = None, repo_root: Optional[str] = None) -> List[Dict[str, object]]:
    issues = []
    ignore_globs = ignore_globs or DEFAULT_IGNORE
    for path in paths:
        if os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                if _is_ignored(root, ignore_globs, repo_root):
                    dirs[:] = []
                    continue
                if ".git" in root.split(os.sep):
                    dirs[:] = []
                    continue
                for file_name in files:
                    full_path = os.path.join(root, file_name)
                    if _is_ignored(full_path, ignore_globs, repo_root):
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
                    issues.extend(scan_text(content, full_path))
            continue
        if not os.path.isfile(path):
            continue
        if _is_ignored(path, ignore_globs, repo_root):
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
        issues.extend(scan_text(content, path))
    return issues


def summarize_issues(issues: List[Dict[str, object]]) -> str:
    if not issues:
        return ""
    lines = [f"Detected potential secrets ({len(issues)}):"]
    for issue in issues:
        entry = (
            f"{issue['source']}:{issue['line']} [{issue['matcher']}] - {issue['snippet']}"
        )
        if issue.get("entropy") is not None:
            entry += f" (entropy={issue['entropy']})"
        lines.append(entry)
    return "\n".join(lines)
