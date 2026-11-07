"""Scanner engine for detecting secrets in files and git staged changes."""

import base64
import fnmatch
import os
import re
import subprocess
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Dict, List, Optional, Any

from .config import CustomRule
from .utils import is_text_bytes, sanitize_snippet, shannon_entropy
from .risk_scoring import get_risk_score

RULE_PACK_VERSION = "1"

SECRET_PATTERNS = {
    "AWS Access Key ID": re.compile(
        r"\b(?:AKIA|ASIA|AGPA|AIDA|ANPA|AROA|AIPA|ANVA)[0-9A-Z]{16}\b"
    ),
    "AWS Secret Access Key": re.compile(
        r"""(?i)\baws[_\-]?secret[_\-]?access[_\-]?key\b\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])["']?"""
    ),
    "Google API Key": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    "Stripe API Key": re.compile(r"\b(?:sk|rk)_(?:test|live)_[A-Za-z0-9]{24,}\b"),
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
        r"(?i)(?<![A-Za-z0-9])[A-Za-z0-9_-]*?"
        r"(?:api[_\-]?key|app[_\-]?key|secret(?:[_\-]?key(?:[_\-]?base)?)?"
        r"|master[_\-]?key|token|password|passwd|pass|auth|credential|"
        r"client[_\-]?secret|private[_\-]?key|oauth[_\-]?token)"
        r"(?![A-Za-z0-9])[\"']?\s*[:=]\s*[\"']?(?:base64:)?"
        r"([A-Za-z0-9_\-+\/=]{16,})[\"']?"
    ),
}
PRIVATE_KEY_BLOCK_PATTERN = re.compile(
    r"-----BEGIN (?P<key_type>[A-Z0-9 ]*PRIVATE KEY)-----"
    r".*?-----END (?P=key_type)-----",
    re.DOTALL,
)
SUPPRESSION_DIRECTIVE_PATTERN = re.compile(
    r"(?i)(?:#|//|/\*)\s*secret[-_]?sentinel:\s*"
    r"(?P<action>disable[-_]next[-_]line|ignore)\b(?P<metadata>.*?)(?:\*/)?\s*$"
)
SUPPRESSION_EXPIRY_PATTERN = re.compile(r"(?i)\bexpires?\s*[:=]\s*([^\s;,*/]+)")
SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"""(?i)(?:^|[\W_])["']?"""
    r"""(?:secret|token|api[_\-]?key|password|passwd|auth|credential|client_secret|private_key|oauth[_\-]?token)"""
    r"""(?:[_\-](?:secret|token|key|password|credential|value))?["']?\s*[:=]\s*"""
    r"""(?P<quote>["'])(?P<value>[^"']+)(?P=quote)"""
)
PLACEHOLDER_VALUE_PATTERN = re.compile(
    r"(?i)^(?:"
    r"\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*"
    r"|\{\{[^{}]+\}\}|<[A-Za-z_][A-Za-z0-9 _-]*>"
    r"|"
    r"your(?:[_-](?:api[_-]?key|token|secret|password|credential))?[_-]?here"
    r"|replace[_-](?:with[_-])?.+"
    r"|change[_-](?:this|me)(?:[_-].*)?"
    r"|insert[_-](?:your[_-])?.+"
    r"|placeholder|example|sample|dummy|redacted|x{3,}"
    r")$"
)
NETRC_PASSWORD_PATTERN = re.compile(
    r"(?i)\b(?:password|passwd|pass)\s+['\"]?(\S+)"
)
PGPASS_ENTRY_PATTERN = re.compile(
    r"^([^:#\s][^:]*):([^:]*):([^:]*):([^:]*):((?:\\.|[^:\s])+)\s*$"
)
DOCKER_AUTH_PATTERN = re.compile(
    r"""(?i)["']auth["']\s*:\s*["']([A-Za-z0-9+/]+={0,2})["']"""
)
DIFF_HUNK_PATTERN = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
ENTROPY_THRESHOLD = 4.6
MIN_ENTROPY_LENGTH = 24
MAX_ENCODED_VALUE_LENGTH = 4096
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


@dataclass
class ScanCoverage:
    """Counts files scanned and skipped during an explicit disk-path scan."""

    scanned_files: int = 0
    ignored_paths: int = 0
    binary_files: int = 0
    unreadable_paths: int = 0
    missing_paths: int = 0

    def as_dict(self) -> Dict[str, int]:
        """Return coverage counts in a serialization-friendly form."""
        return {
            "scanned_files": self.scanned_files,
            "ignored_paths": self.ignored_paths,
            "binary_files": self.binary_files,
            "unreadable_paths": self.unreadable_paths,
            "missing_paths": self.missing_paths,
        }


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


def get_staged_paths(repo_root: Optional[str] = None) -> List[str]:
    """List paths for staged files whose contents can be scanned.

    Args:
        repo_root: Optional working directory for the Git command.

    Returns:
        List of relative paths to staged files.
    """
    result = _run_git_command(
        [
            "diff",
            "--cached",
            "--name-only",
            "-z",
            "--diff-filter=ACMRT",
            "--",
        ],
        cwd=repo_root,
        text=False,
    )
    if result.returncode != 0:
        raise RuntimeError("Unable to read staged files for scanning.")
    return [
        os.fsdecode(raw_path)
        for raw_path in result.stdout.split(b"\0")
        if raw_path
    ]


def get_staged_content(path: str, repo_root: Optional[str] = None) -> Optional[str]:
    """Fetch text content of a staged file from the Git index.

    Args:
        path: Path of the file in the Git index.
        repo_root: Optional working directory for the Git command.

    Returns:
        Text content if file is plain text, or None if binary.

    Raises:
        RuntimeError: If Git cannot read the staged file.
    """
    result = _run_git_command(
        ["--literal-pathspecs", "show", f":0:{path}"],
        cwd=repo_root,
        text=False,
    )
    if result.returncode != 0:
        raise RuntimeError("Unable to read staged file content.")
    if not is_text_bytes(result.stdout):
        return None
    return result.stdout.decode("utf-8", errors="replace")


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
            if rel != os.pardir and not rel.startswith(os.pardir + os.sep):
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


def _suppression_is_active(metadata: str) -> bool:
    """Return whether a suppression directive has not expired."""
    expiry_status = _suppression_expiry_status(metadata)
    return expiry_status in {"active", "missing-expiry"}


def _suppression_expiry_status(metadata: str) -> str:
    """Return the expiry state of a suppression directive."""
    expiry_match = SUPPRESSION_EXPIRY_PATTERN.search(metadata)
    if not expiry_match:
        return "missing-expiry"

    expiry_text = expiry_match.group(1)
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", expiry_text):
        return "invalid-expiry"
    try:
        expiry = date.fromisoformat(expiry_text)
    except ValueError:
        return "invalid-expiry"
    return "expired" if date.today() > expiry else "active"


def _suppression_has_reason(metadata: str) -> bool:
    """Return whether a suppression directive includes a non-empty reason."""
    reason_match = re.search(r"(?i)\breason\s*[:=]\s*(.*)", metadata)
    if not reason_match:
        return False
    reason = reason_match.group(1).split(";", 1)[0].strip(" \t,*/")
    return bool(reason)


def _scan_line(
    line: str,
    lineno: int,
    source: str,
    custom_rules: Optional[List[CustomRule]] = None,
) -> List[Dict[str, Any]]:
    """Return unsuppressed detector matches found on one source line."""
    issues: List[Dict[str, Any]] = []
    source_path = Path(source)
    if source_path.name == ".netrc":
        for match in NETRC_PASSWORD_PATTERN.finditer(line):
            if PLACEHOLDER_VALUE_PATTERN.fullmatch(match.group(1)):
                continue
            issues.append(_build_issue(
                source,
                lineno,
                line,
                "Netrc Password",
                match.group(1),
            ))
    if source_path.name == ".pgpass":
        match = PGPASS_ENTRY_PATTERN.fullmatch(line)
        if (
            match
            and match.group(5) != "*"
            and not PLACEHOLDER_VALUE_PATTERN.fullmatch(match.group(5))
        ):
            issues.append(_build_issue(
                source,
                lineno,
                line,
                "PostgreSQL Password File",
                match.group(5),
            ))
    if source_path.name == ".dockercfg" or (
        source_path.name == "config.json" and ".docker" in source_path.parts
    ):
        for match in DOCKER_AUTH_PATTERN.finditer(line):
            try:
                decoded_auth = base64.b64decode(match.group(1), validate=True)
            except ValueError:
                continue
            if decoded_auth.partition(b":")[0] and decoded_auth.partition(b":")[2]:
                issues.append(_build_issue(
                    source,
                    lineno,
                    line,
                    "Docker Registry Auth",
                    match.group(1),
                ))
    for name, pattern in SECRET_PATTERNS.items():
        for match in pattern.finditer(line):
            value = match.group(1) if match.groups() else match.group(0)
            if name == "Generic Secret Assignment" and any(
                issue["matcher"] == "Docker Registry Auth"
                and issue["value"] == value
                for issue in issues
            ):
                continue
            if name in {
                "Database Connection URI",
                "Generic Secret Assignment",
            } and PLACEHOLDER_VALUE_PATTERN.fullmatch(value):
                continue
            severity = get_risk_score(name)
            issues.append(
                {
                    "source": source,
                    "line": lineno,
                    "matcher": name,
                    "value": value,
                    "snippet": line.strip(),
                    "confidence": (
                        "medium"
                        if name == "Generic Secret Assignment"
                        else "low"
                        if name == "Private Key"
                        else "high"
                    ),
                    "reason": (
                        "private-key-header"
                        if name == "Private Key"
                        else "pattern"
                    ),
                    "severity": severity.name,
                }
            )
    for rule in custom_rules or []:
        for match in rule.pattern.finditer(line):
            value = match.group(0)
            issues = [
                issue
                for issue in issues
                if issue["reason"] == "custom-pattern" or issue["value"] != value
            ]
            issues.append(
                {
                    "source": source,
                    "line": lineno,
                    "matcher": rule.name,
                    "value": value,
                    "snippet": line.strip(),
                    "confidence": "medium",
                    "reason": "custom-pattern",
                    "severity": rule.severity.name,
                }
            )
    for match in SECRET_ASSIGNMENT_PATTERN.finditer(line):
        value = match.group("value")
        if len(value) < MIN_ENTROPY_LENGTH:
            continue
        if any(issue["value"] == value for issue in issues):
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


def _build_issue(
    source: str,
    lineno: int,
    line: str,
    matcher: str,
    value: str,
) -> Dict[str, Any]:
    """Build a standard pattern finding."""
    severity = get_risk_score(matcher)
    return {
        "source": source,
        "line": lineno,
        "matcher": matcher,
        "value": value,
        "snippet": line.strip(),
        "confidence": "high",
        "reason": "pattern",
        "severity": severity.name,
    }


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
    suppressed_lines = set()

    for lineno, line in enumerate(lines, start=1):
        if skip_next_line:
            skip_next_line = False
            suppressed_lines.add(lineno)
            continue

        directive = SUPPRESSION_DIRECTIVE_PATTERN.search(line)
        if directive and _suppression_is_active(directive.group("metadata")):
            if directive.group("action").lower().startswith("disable"):
                skip_next_line = True
            else:
                suppressed_lines.add(lineno)
                continue
            continue

        issues.extend(_scan_line(line, lineno, source, custom_rules))

    for match in PRIVATE_KEY_BLOCK_PATTERN.finditer(content):
        lineno = content.count("\n", 0, match.start()) + 1
        if lineno in suppressed_lines:
            continue
        issues = [
            issue
            for issue in issues
            if not (
                issue["matcher"] == "Private Key"
                and issue["line"] == lineno
            )
        ]
        header = lines[lineno - 1].strip() if lineno <= len(lines) else ""
        issues.append(
            {
                "source": source,
                "line": lineno,
                "matcher": "Private Key",
                "value": match.group(0),
                "snippet": header,
                "confidence": "high",
                "reason": "private-key-block",
                "severity": get_risk_score("Private Key").name,
            }
        )

    for issue in list(issues):
        if issue["matcher"] not in {
            "Generic Secret Assignment",
            "High entropy string",
        }:
            continue
        encoded_value = str(issue["value"])
        if not 24 <= len(encoded_value) <= MAX_ENCODED_VALUE_LENGTH:
            continue
        padded_value = encoded_value + "=" * (-len(encoded_value) % 4)
        try:
            decoded = base64.b64decode(
                padded_value,
                altchars=b"-_",
                validate=True,
            ).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if any(ord(character) < 32 and character not in "\r\n\t" for character in decoded):
            continue
        for name, pattern in SECRET_PATTERNS.items():
            if name == "Generic Secret Assignment":
                continue
            decoded_match = pattern.search(decoded)
            if not decoded_match:
                continue
            issues = [finding for finding in issues if finding is not issue]
            issues.append(
                {
                    "source": source,
                    "line": issue["line"],
                    "matcher": name,
                    "value": encoded_value,
                    "snippet": issue["snippet"],
                    "confidence": "medium",
                    "reason": "encoded-pattern",
                    "severity": get_risk_score(name).name,
                }
            )
            break
    return issues


def audit_suppressions_text(
    content: str,
    source: str,
    custom_rules: Optional[List[CustomRule]] = None,
) -> List[Dict[str, Any]]:
    """Audit suppression directives without returning source or finding values.

    Args:
        content: Source text to inspect.
        source: Source identifier, preferably relative to the repository.
        custom_rules: Optional configured detection rules.

    Returns:
        Suppression records containing only location, target line, and statuses.
    """
    suppressions: List[Dict[str, Any]] = []
    lines = content.splitlines()
    for lineno, line in enumerate(lines, start=1):
        directive = SUPPRESSION_DIRECTIVE_PATTERN.search(line)
        if not directive:
            continue

        metadata = directive.group("metadata")
        action = directive.group("action").lower()
        target_line = lineno if action == "ignore" else lineno + 1
        target_exists = target_line <= len(lines)
        statuses: List[str] = []
        if not _suppression_has_reason(metadata):
            statuses.append("missing-reason")

        expiry_status = _suppression_expiry_status(metadata)
        if expiry_status != "active":
            statuses.append(expiry_status)

        is_active = expiry_status in {"active", "missing-expiry"}
        has_finding = (
            target_exists
            and bool(
                _scan_line(
                    lines[target_line - 1],
                    target_line,
                    source,
                    custom_rules,
                )
            )
        )
        if is_active and not has_finding:
            statuses.append("unused")
        if not statuses:
            statuses.append("active")

        suppressions.append(
            {
                "source": source,
                "line": lineno,
                "target_line": target_line if target_exists else None,
                "statuses": statuses,
            }
        )
    return suppressions


def audit_suppressions_in_repo(
    repo_root: str,
    ignore_globs: Optional[List[str]] = None,
    custom_rules: Optional[List[CustomRule]] = None,
) -> List[Dict[str, Any]]:
    """Audit inline suppressions in readable text files under a repository root.

    Args:
        repo_root: Repository directory to inspect.
        ignore_globs: Optional path patterns to exclude.
        custom_rules: Optional configured detection rules.

    Returns:
        Suppression audit records containing no source text or secret values.

    Raises:
        OSError: If a repository file cannot be read.
        ValueError: If repo_root is not a directory.
    """
    root_path = Path(repo_root)
    if not root_path.is_dir():
        raise ValueError("A repository directory is required.")

    active_ignores = DEFAULT_IGNORE if ignore_globs is None else ignore_globs
    suppressions: List[Dict[str, Any]] = []
    for current_root, dirs, file_names in os.walk(root_path, followlinks=False):
        dirs.sort()
        file_names.sort()
        dirs[:] = [
            directory
            for directory in dirs
            if directory != ".git"
            and not _is_ignored(
                os.path.join(current_root, directory),
                active_ignores,
                repo_root,
            )
        ]
        for file_name in file_names:
            full_path = os.path.join(current_root, file_name)
            if os.path.islink(full_path) or _is_ignored(
                full_path, active_ignores, repo_root
            ):
                continue
            with open(full_path, "rb") as handle:
                data = handle.read()
            if not is_text_bytes(data[:2048]):
                continue

            source = _sanitize_source_path(full_path, repo_root)
            content = data.decode("utf-8", errors="replace")
            suppressions.extend(
                audit_suppressions_text(content, source, custom_rules)
            )
    return suppressions


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
    effective_repo_root = repo_root or get_git_root()
    active_ignores = DEFAULT_IGNORE if ignore_globs is None else ignore_globs
    for path in get_staged_paths(effective_repo_root):
        absolute_path = os.path.join(effective_repo_root or os.getcwd(), path)
        if _is_ignored(absolute_path, active_ignores, effective_repo_root):
            continue
        content = get_staged_content(path, effective_repo_root)
        if content is None:
            continue
        safe_path = _sanitize_source_path(path, effective_repo_root)
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

    return _scan_git_commits(
        repo_root,
        commits_result.stdout.splitlines(),
        ignore_globs=ignore_globs,
        custom_rules=custom_rules,
    )


def scan_git_push_updates(
    repo_root: str,
    updates: str,
    ignore_globs: Optional[List[str]] = None,
    custom_rules: Optional[List[CustomRule]] = None,
) -> List[Dict[str, Any]]:
    """Scan commits introduced by Git pre-push ref updates.

    Args:
        repo_root: Repository directory.
        updates: Git pre-push hook update lines from standard input.
        ignore_globs: Optional path patterns to exclude.
        custom_rules: Optional configured detection rules.

    Returns:
        Findings in commits reachable from local refs but not their remote refs.

    Raises:
        RuntimeError: If update input or repository history cannot be read.
    """
    zero_sha_by_length = {"0" * 40, "0" * 64}
    commit_pattern = re.compile(r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
    commits: List[str] = []
    seen_commits: set[str] = set()

    for update in updates.splitlines():
        if not update.strip():
            continue
        fields = update.split()
        if len(fields) != 4:
            raise RuntimeError("Invalid pre-push update data.")

        _local_ref, local_sha, _remote_ref, remote_sha = fields
        if (
            not commit_pattern.fullmatch(local_sha)
            or not commit_pattern.fullmatch(remote_sha)
            or len(local_sha) != len(remote_sha)
        ):
            raise RuntimeError("Invalid pre-push update data.")
        if local_sha in zero_sha_by_length:
            continue

        revisions = [local_sha]
        if remote_sha not in zero_sha_by_length:
            revisions.extend(["--not", remote_sha])
        commit_result = _run_git_command(
            ["rev-list", "--reverse", *revisions],
            cwd=repo_root,
        )
        if commit_result.returncode != 0:
            raise RuntimeError("Unable to read commits being pushed.")
        for commit in commit_result.stdout.splitlines():
            if commit not in seen_commits:
                seen_commits.add(commit)
                commits.append(commit)

    return _scan_git_commits(
        repo_root,
        commits,
        ignore_globs=ignore_globs,
        custom_rules=custom_rules,
    )


def scan_git_commit_range(
    repo_root: str,
    base: str,
    head: str,
    ignore_globs: Optional[List[str]] = None,
    custom_rules: Optional[List[CustomRule]] = None,
) -> List[Dict[str, Any]]:
    """Scan commits after base through head, including findings later removed.

    Findings already present in the base snapshot are excluded for files
    touched by the range.
    """
    if not base or base.startswith("-") or not head or head.startswith("-"):
        raise ValueError("Valid base and head commits or refs are required.")

    resolved: List[str] = []
    for revision in (base, head):
        result = _run_git_command(
            [
                "rev-parse",
                "--verify",
                "--quiet",
                "--end-of-options",
                f"{revision}^{{commit}}",
            ],
            cwd=repo_root,
        )
        if result.returncode != 0:
            raise ValueError("Unable to resolve commit range.")
        resolved.append(result.stdout.strip())
    base_commit, head_commit = resolved

    ancestor_result = _run_git_command(
        ["merge-base", "--is-ancestor", base_commit, head_commit],
        cwd=repo_root,
    )
    if ancestor_result.returncode != 0:
        raise ValueError("The base commit must be an ancestor of the head commit.")

    commits_result = _run_git_command(
        ["rev-list", "--reverse", f"{base_commit}..{head_commit}"],
        cwd=repo_root,
    )
    if commits_result.returncode != 0:
        raise RuntimeError("Unable to read commits in the requested range.")
    commits = commits_result.stdout.splitlines()
    if not commits:
        return []

    changed_paths: set[str] = set()
    for commit in commits:
        changed_result = _run_git_command(
            [
                "diff-tree",
                "--root",
                "--no-commit-id",
                "--name-only",
                "-r",
                "-m",
                "-z",
                commit,
            ],
            cwd=repo_root,
            text=False,
        )
        if changed_result.returncode != 0:
            raise RuntimeError("Unable to identify files changed in commit range.")
        changed_paths.update(
            os.fsdecode(raw_path)
            for raw_path in changed_result.stdout.split(b"\0")
            if raw_path
        )

    base_issues = _scan_git_tree_paths(
        repo_root,
        base_commit,
        changed_paths,
        ignore_globs=ignore_globs,
        custom_rules=custom_rules,
    )
    preexisting = {
        (issue["source"], issue["matcher"], issue["value"])
        for issue in base_issues
    }
    return _scan_git_commits(
        repo_root,
        commits,
        ignore_globs=ignore_globs,
        custom_rules=custom_rules,
        excluded_findings=preexisting,
    )


def _scan_git_commits(
    repo_root: str,
    commits: List[str],
    ignore_globs: Optional[List[str]] = None,
    custom_rules: Optional[List[CustomRule]] = None,
    excluded_findings: Optional[set[tuple[str, str, str]]] = None,
) -> List[Dict[str, Any]]:
    """Scan changed blobs in a parent-before-child commit sequence."""
    active_ignores = DEFAULT_IGNORE if ignore_globs is None else ignore_globs
    seen_findings: set[tuple[str, str, str]] = set()
    issues: List[Dict[str, Any]] = []

    for commit in commits:
        changed_result = _run_git_command(
            [
                "diff-tree",
                "--root",
                "--no-commit-id",
                "--name-only",
                "-r",
                "-m",
                "-z",
                commit,
            ],
            cwd=repo_root,
            text=False,
        )
        if changed_result.returncode != 0:
            raise RuntimeError("Unable to identify files changed in pushed commits.")
        changed_paths = {
            os.fsdecode(raw_path)
            for raw_path in changed_result.stdout.split(b"\0")
            if raw_path
        }
        for issue in _scan_git_tree_paths(
            repo_root,
            commit,
            changed_paths,
            ignore_globs=active_ignores,
            custom_rules=custom_rules,
        ):
            finding_key = (issue["source"], issue["matcher"], issue["value"])
            if finding_key in seen_findings or (
                excluded_findings is not None and finding_key in excluded_findings
            ):
                continue
            seen_findings.add(finding_key)
            issue["commit"] = commit
            issues.append(issue)

    return issues


def _scan_git_tree_paths(
    repo_root: str,
    commit: str,
    paths: set[str],
    ignore_globs: Optional[List[str]] = None,
    custom_rules: Optional[List[CustomRule]] = None,
) -> List[Dict[str, Any]]:
    """Scan selected text blobs in a Git commit snapshot."""
    if not paths:
        return []

    tree_result = _run_git_command(
        [
            "--literal-pathspecs",
            "ls-tree",
            "-r",
            "-z",
            "--full-tree",
            commit,
            "--",
            *sorted(paths),
        ],
        cwd=repo_root,
        text=False,
    )
    if tree_result.returncode != 0:
        raise RuntimeError("Unable to read repository history for scanning.")

    active_ignores = DEFAULT_IGNORE if ignore_globs is None else ignore_globs
    issues: List[Dict[str, Any]] = []
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
        issues.extend(scan_text(content, source, custom_rules=custom_rules))
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

    active_ignores = DEFAULT_IGNORE if ignore_globs is None else ignore_globs
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
    coverage: Optional[ScanCoverage] = None,
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
            def record_walk_error(_: OSError) -> None:
                if coverage is not None:
                    coverage.unreadable_paths += 1

            for root, dirs, files in os.walk(path, onerror=record_walk_error):
                if _is_ignored(root, active_ignores, repo_root):
                    if coverage is not None:
                        coverage.ignored_paths += 1
                    dirs[:] = []
                    continue
                if ".git" in root.split(os.sep):
                    if coverage is not None:
                        coverage.ignored_paths += 1
                    dirs[:] = []
                    continue
                for file_name in files:
                    full_path = os.path.join(root, file_name)
                    if _is_ignored(full_path, active_ignores, repo_root):
                        if coverage is not None:
                            coverage.ignored_paths += 1
                        continue
                    try:
                        with open(full_path, "rb") as handle:
                            data = handle.read()
                    except OSError:
                        if coverage is not None:
                            coverage.unreadable_paths += 1
                        continue
                    if not is_text_bytes(data[:2048]):
                        if coverage is not None:
                            coverage.binary_files += 1
                        continue
                    content = data.decode("utf-8", errors="replace")
                    if coverage is not None:
                        coverage.scanned_files += 1
                    safe_source = _sanitize_source_path(full_path, repo_root)
                    issues.extend(scan_text(content, safe_source, custom_rules=custom_rules))
            continue
        if not os.path.isfile(path):
            if coverage is not None:
                coverage.missing_paths += 1
            continue
        if _is_ignored(path, active_ignores, repo_root):
            if coverage is not None:
                coverage.ignored_paths += 1
            continue
        try:
            with open(path, "rb") as handle:
                data = handle.read()
        except OSError:
            if coverage is not None:
                coverage.unreadable_paths += 1
            continue
        if not is_text_bytes(data[:2048]):
            if coverage is not None:
                coverage.binary_files += 1
            continue
        content = data.decode("utf-8", errors="replace")
        if coverage is not None:
            coverage.scanned_files += 1
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
