import os
import re
import subprocess
from typing import List, Dict, Optional

from .utils import shannon_entropy, is_text_bytes

SECRET_PATTERNS = {
    "AWS Secret Access Key": re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|ANPA|AROA|AIPA|ANVA)[0-9A-Z]{16}\b"),
    "Google API Key": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    "GitHub Token": re.compile(r"\bghp_[A-Za-z0-9_]{36}\b"),
    "Slack Token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "SSH Private Key": re.compile(r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PRIVATE) KEY-----"),
    "JWT": re.compile(r"\beyJ[0-9A-Za-z_\-]+\.[0-9A-Za-z_\-]+\.[0-9A-Za-z_\-]+\b"),
    "Generic Secret Assignment": re.compile(
        r"(?i)\b(?:api[_\-]?key|secret|token|password|passwd|auth|credential|client_secret|private_key)\b\s*[:=]\s*[\"']?([A-Za-z0-9_\-+\/=]{16,})[\"']?"
    ),
}
SECRET_STRING_PATTERN = re.compile(r"[\"']([A-Za-z0-9+/=_.-]{24,})[\"']")
ENTROPY_THRESHOLD = 4.6
MIN_ENTROPY_LENGTH = 24


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


def _line_has_secret_keyword(line: str) -> bool:
    return bool(re.search(r"(?i)\b(secret|token|api[_\-]?key|password|passwd|auth|credential|client_secret|private_key)\b", line))


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


def scan_staged_files() -> List[Dict[str, object]]:
    issues = []
    for path in get_staged_paths():
        content = get_staged_content(path)
        if content is None:
            continue
        issues.extend(scan_text(content, path))
    return issues


def scan_paths(paths: List[str]) -> List[Dict[str, object]]:
    issues = []
    for path in paths:
        if os.path.isdir(path):
            for root, _, files in os.walk(path):
                if ".git" in root.split(os.sep):
                    continue
                for file_name in files:
                    full_path = os.path.join(root, file_name)
                    issues.extend(scan_paths([full_path]))
            continue
        if not os.path.isfile(path):
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
    lines = ["Detected potential secrets:"]
    for issue in issues:
        entry = (
            f"{issue['source']}:{issue['line']} [{issue['matcher']}] - {issue['snippet']}"
        )
        if issue.get("entropy") is not None:
            entry += f" (entropy={issue['entropy']})"
        lines.append(entry)
    return "\n".join(lines)
