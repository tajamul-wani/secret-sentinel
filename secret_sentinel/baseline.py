"""Secret-free baseline storage for known scanner findings."""

import hashlib
import hmac
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple


class ScanBaseline:
    """Stores fingerprints for findings that already exist in a repository."""

    VERSION = 1
    DEFAULT_PATH = ".secret-sentinel/baseline.json"
    FINGERPRINT_PATTERN = re.compile(r"[0-9a-f]{64}")
    KEY_ENVIRONMENT_VARIABLE = "SECRET_SENTINEL_BASELINE_KEY"
    MINIMUM_KEY_LENGTH = 32

    def __init__(self, repo_root: str) -> None:
        self.path = Path(repo_root) / self.DEFAULT_PATH
        key = os.environ.get(self.KEY_ENVIRONMENT_VARIABLE, "")
        if len(key.encode("utf-8")) < self.MINIMUM_KEY_LENGTH:
            raise ValueError(
                f"{self.KEY_ENVIRONMENT_VARIABLE} must be set to at least "
                f"{self.MINIMUM_KEY_LENGTH} bytes for baseline operations."
            )
        self._key = key.encode("utf-8")

    def fingerprint(self, issue: Dict[str, Any]) -> str:
        """Create a keyed fingerprint without persisting the detected value."""
        source = issue.get("source")
        matcher = issue.get("matcher")
        value = issue.get("value")
        if not all(isinstance(item, str) and item for item in (source, matcher, value)):
            raise ValueError("Finding is missing source, matcher, or value.")
        identity = json.dumps([source, matcher, value], ensure_ascii=True, separators=(",", ":"))
        return hmac.new(
            self._key,
            identity.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def load(self) -> Set[str]:
        """Load and validate baseline fingerprints."""
        with self.path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, dict) or data.get("version") != self.VERSION:
            raise ValueError("Unsupported or invalid baseline format.")
        fingerprints = data.get("fingerprints")
        if not isinstance(fingerprints, list) or any(
            not isinstance(item, str) or not self.FINGERPRINT_PATTERN.fullmatch(item)
            for item in fingerprints
        ):
            raise ValueError("Invalid fingerprint list in baseline.")
        return set(fingerprints)

    def save(self, issues: List[Dict[str, Any]]) -> None:
        """Atomically save issue fingerprints, never raw finding values."""
        fingerprints = sorted({self.fingerprint(issue) for issue in issues})
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = ""
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.path.parent,
                prefix=f".{self.path.name}.",
                suffix=".tmp",
                delete=False,
            ) as handle:
                temporary_path = handle.name
                json.dump(
                    {"version": self.VERSION, "fingerprints": fingerprints},
                    handle,
                    indent=2,
                )
                handle.write("\n")
            os.replace(temporary_path, self.path)
        finally:
            if temporary_path and os.path.exists(temporary_path):
                os.unlink(temporary_path)

    def filter_issues(self, issues: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int]:
        """Return issues absent from the baseline and the number suppressed."""
        fingerprints = self.load()
        new_issues = [
            issue for issue in issues if self.fingerprint(issue) not in fingerprints
        ]
        return new_issues, len(issues) - len(new_issues)
