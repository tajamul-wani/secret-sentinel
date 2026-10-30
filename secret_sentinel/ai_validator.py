"""Optional AI-assisted validator for detected secrets and potential false positives."""

import json
import logging
import os
import subprocess
from typing import Any, Dict, List, Optional

logger = logging.getLogger("secret_sentinel")

DEFAULT_OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2")
OLLAMA_EXECUTABLE = os.getenv("OLLAMA_BIN", "ollama")
GEMINI_API_URL = os.getenv("GEMINI_API_URL", "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent")


def _run_command(args: List[str], cwd: Optional[str] = None, timeout: int = 5) -> Optional[subprocess.CompletedProcess]:
    """Execute a local command with timeout and error handling.

    Args:
        args: Command-line arguments.
        cwd: Optional working directory.
        timeout: Timeout in seconds.

    Returns:
        CompletedProcess if successful, or None on failure/timeout.
    """
    try:
        return subprocess.run(
            args,
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None


def _query_ollama(prompt: str) -> Optional[str]:
    """Query a local Ollama instance for validation if available.

    Args:
        prompt: Evaluation prompt.

    Returns:
        Response string if query succeeded, None otherwise.
    """
    result = _run_command([OLLAMA_EXECUTABLE, "run", DEFAULT_OLLAMA_MODEL, prompt])
    if result and result.returncode == 0:
        return result.stdout.strip()
    return None


def _query_gemini(prompt: str) -> Optional[str]:
    """Query optional cloud AI endpoint if configured.

    Args:
        prompt: Evaluation prompt.

    Returns:
        Response string if query succeeded, None otherwise.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return None

    headers = {
        "Content-Type": "application/json",
    }
    url = f"{GEMINI_API_URL}?key={api_key}"
    payload = {
        "contents": [
            {
                "parts": [{"text": prompt}]
            }
        ],
        "generationConfig": {
            "maxOutputTokens": 64,
        },
    }

    try:
        import urllib.request
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            if isinstance(body, dict):
                candidates = body.get("candidates", [])
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    if parts:
                        return str(parts[0].get("text", "")).strip()
    except Exception:
        return None
    return None


def validate_issue(issue: Dict[str, Any], surrounding: str) -> bool:
    """Evaluate whether a detected secret is likely real or a false positive.

    If AI services are unreachable or encounter errors, gracefully falls back
    to rule confidence (safe-by-default behavior).

    Args:
        issue: Issue dictionary describing finding.
        surrounding: Surrounding code snippet context.

    Returns:
        True if issue is considered a real secret, False if false positive.
    """
    prompt = (
        "Inspect the following code snippet and determine whether the highlighted string "
        "is a real secret/API key or a mock/test placeholder.\n\n"
        f"Code:\n{surrounding}\n\n"
        f"Potential secret: {issue.get('value')}\n\n"
        "Answer with: REAL_SECRET or FALSE_POSITIVE."
    )
    response = _query_ollama(prompt) or _query_gemini(prompt)
    if not response:
        return issue.get("confidence") == "high"

    normalized = response.strip().upper()
    if "FALSE_POSITIVE" in normalized:
        return False
    return True


def build_surrounding_snippet(content: str, line_number: int, context: int = 2) -> str:
    """Extract context lines surrounding a given line number.

    Args:
        content: Complete file content.
        line_number: Target line number (1-indexed).
        context: Number of lines before and after to include.

    Returns:
        Joined multi-line string containing snippet context.
    """
    lines = content.splitlines()
    start = max(0, line_number - 1 - context)
    end = min(len(lines), line_number + context)
    return "\n".join(lines[start:end])


def validate_issues(issues: List[Dict[str, Any]], path: str, content: str) -> List[Dict[str, Any]]:
    """Validate a collection of detected issues using context snippets.

    Args:
        issues: List of detected issues.
        path: Path identifier of the source file.
        content: Full text content of the source file.

    Returns:
        Filtered list containing only verified issues.
    """
    verified: List[Dict[str, Any]] = []
    for issue in issues:
        surrounding = build_surrounding_snippet(content, int(issue.get("line", 1)))
        if validate_issue(issue, surrounding):
            verified.append(issue)
    return verified
