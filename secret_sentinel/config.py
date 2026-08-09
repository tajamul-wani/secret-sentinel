import configparser
from pathlib import Path
from typing import List

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


class SecretSentinelConfig:
    def __init__(self, ignore_globs: List[str], ai_enabled: bool) -> None:
        self.ignore_globs = ignore_globs
        self.ai_enabled = ai_enabled

    @classmethod
    def load(cls, repo_root: str, file_name: str = ".secret-sentinel.ini") -> "SecretSentinelConfig":
        ignore_globs = DEFAULT_IGNORE.copy()
        ai_enabled = True
        config_path = Path(repo_root) / file_name
        if config_path.is_file():
            parser = configparser.ConfigParser()
            parser.read(config_path)
            if parser.has_section("secret-sentinel"):
                raw_ignore = parser.get("secret-sentinel", "ignore_paths", fallback="")
                ignore_globs.extend(
                    [item.strip() for item in raw_ignore.split(",") if item.strip()]
                )
                ai_enabled = parser.getboolean("secret-sentinel", "ai_enabled", fallback=True)
        return cls(ignore_globs, ai_enabled)
