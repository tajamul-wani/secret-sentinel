"""Configuration manager for Secret Sentinel."""

import configparser
from pathlib import Path
from typing import List

from .risk_scoring import SeverityLevel

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


class SecretSentinelConfig:
    """Represents runtime configuration loaded from local ini file or defaults."""

    def __init__(
        self,
        ignore_globs: List[str],
        ai_enabled: bool,
        fail_on: SeverityLevel = SeverityLevel.LOW,
    ) -> None:
        """Initialize configuration object.

        Args:
            ignore_globs: List of glob patterns to ignore during scans.
            ai_enabled: Whether AI validation is enabled.
            fail_on: Minimum severity level that causes scan to fail.
        """
        self.ignore_globs = ignore_globs
        self.ai_enabled = ai_enabled
        self.fail_on = fail_on

    @classmethod
    def load(
        cls,
        repo_root: str,
        file_name: str = ".secret-sentinel.ini",
        ignore_file_name: str = ".secretignore",
    ) -> "SecretSentinelConfig":
        """Load configuration from a file or fall back to defaults.

        Also parses .secretignore if present in the repository root.

        Args:
            repo_root: Root directory of the repository.
            file_name: Configuration file name.
            ignore_file_name: Ignore file name (defaults to .secretignore).

        Returns:
            Configured SecretSentinelConfig instance.
        """
        ignore_globs = DEFAULT_IGNORE.copy()
        ai_enabled = True
        fail_on = SeverityLevel.LOW

        root_path = Path(repo_root)

        # Parse .secretignore if available
        secretignore_path = root_path / ignore_file_name
        if secretignore_path.is_file():
            try:
                with open(secretignore_path, "r", encoding="utf-8") as handle:
                    for line in handle:
                        cleaned = line.strip()
                        if cleaned and not cleaned.startswith("#"):
                            ignore_globs.append(cleaned)
            except OSError:
                pass

        # Parse .secret-sentinel.ini if available
        config_path = root_path / file_name
        if config_path.is_file():
            parser = configparser.ConfigParser()
            parser.read(config_path)
            if parser.has_section("secret-sentinel"):
                raw_ignore = parser.get("secret-sentinel", "ignore_paths", fallback="")
                ignore_globs.extend(
                    [item.strip() for item in raw_ignore.split(",") if item.strip()]
                )
                ai_enabled = parser.getboolean("secret-sentinel", "ai_enabled", fallback=True)

                raw_fail_on = parser.get("secret-sentinel", "fail_on", fallback="LOW").strip().upper()
                try:
                    fail_on = SeverityLevel[raw_fail_on]
                except KeyError:
                    fail_on = SeverityLevel.LOW

        return cls(ignore_globs, ai_enabled, fail_on=fail_on)
