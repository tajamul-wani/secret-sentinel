import os
import json
import re
import subprocess
from typing import Dict, Optional

OLLAMA_EXECUTABLE = "ollama"
GEMINI_API_URL = "https://gemini.googleapis.com/v1/models/"  # placeholder


def _run_command(args, cwd=None, text=True):
    result = subprocess.run(
        args,
        cwd=cwd,
        capture_output=True,
        text=text,
        check=False,
    )
    return result


def _query_ollama(prompt: str) -> Optional[str]:
    try:
        result = _run_command([OLLAMA_EXECUTABLE, "evaluate", "--model", "gpt-4o-mini", prompt])
        if result.returncode != 0:
            return None
        return result.stdout.strip()
    except FileNotFoundError:
        return None


def _query_gemini(prompt: str) -> Optional[str]:
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return None
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    data = {
        "prompt": prompt,
        "max_output_tokens": 256,
    }
    try:
        import urllib.request
        req = urllib.request.Request(
            GEMINI_API_URL,
            data=json.dumps(data).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            if isinstance(body, dict):
                return body.get("text") or body.get("output")
    except Exception:
        return None
    return None


def validate_issue(issue: Dict[str, object], surrounding: str) -> bool:
    prompt = (
        "Inspect the following code snippet and determine whether the highlighted string is a real secret/API key or a mock/test placeholder.\n\n"
        f"Code:\n{surrounding}\n\n"
        f"Potential secret: {issue['value']}\n\n"
        "Answer with: REAL_SECRET or FALSE_POSITIVE."
    )
    response = _query_ollama(prompt) or _query_gemini(prompt)
    if not response:
        return issue.get("confidence") == "high"
    normalized = response.strip().upper()
    if "FALSE" in normalized:
        return False
    return True


def build_surrounding_snippet(content: str, line_number: int, context: int = 2) -> str:
    lines = content.splitlines()
    start = max(0, line_number - 1 - context)
    end = min(len(lines), line_number + context)
    return "\n".join(lines[start:end])


def validate_issues(issues: list, path: str, content: str) -> list:
    verified = []
    for issue in issues:
        surrounding = build_surrounding_snippet(content, issue["line"])
        if validate_issue(issue, surrounding):
            verified.append(issue)
    return verified
