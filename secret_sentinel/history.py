"""History and audit logging module for tracking scan results over time."""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .risk_scoring import SeverityLevel, get_issue_severity


class ScanHistory:
    """Manages scan history records and statistics in local storage."""

    HISTORY_DIR = ".secret-sentinel"
    HISTORY_FILE = "scan_history.jsonl"

    def __init__(self, repo_root: Optional[str] = None) -> None:
        """Initialize history manager.

        Args:
            repo_root: Root directory of the repository. Uses cwd if not provided.
        """
        self.repo_root = repo_root or os.getcwd()
        self.history_dir = Path(self.repo_root) / self.HISTORY_DIR
        self.history_file = self.history_dir / self.HISTORY_FILE

    def ensure_directory(self) -> None:
        """Create history directory if it does not exist."""
        self.history_dir.mkdir(parents=True, exist_ok=True)

    def record_scan(
        self,
        issues: List[Dict[str, Any]],
        scan_type: str = "manual",
        status: str = "completed",
    ) -> None:
        """Record a scan result in history.

        Args:
            issues: List of detected issues.
            scan_type: Type of scan ('staged', 'manual', 'hook').
            status: Status of the scan ('completed', 'blocked', 'error').
        """
        self.ensure_directory()

        severity_counts = self._count_by_severity(issues)

        record = {
            "timestamp": datetime.now().isoformat(),
            "scan_type": scan_type,
            "status": status,
            "total_issues": len(issues),
            "severity_counts": {
                level.name: count
                for level, count in severity_counts.items()
            },
            "issues_summary": self._summarize_issues(issues),
        }

        with open(self.history_file, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")

    def get_history(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Retrieve scan history.

        Args:
            limit: Maximum number of records to return. None for all records.

        Returns:
            List of scan records, newest first.
        """
        if not self.history_file.exists():
            return []

        records: List[Dict[str, Any]] = []
        with open(self.history_file, "r", encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if stripped:
                    try:
                        records.append(json.loads(stripped))
                    except json.JSONDecodeError:
                        continue

        records.reverse()

        if limit is not None:
            records = records[:limit]

        return records

    def get_statistics(self) -> Dict[str, Any]:
        """Compute aggregated statistics from scan history.

        Returns:
            Dictionary with aggregated statistics.
        """
        history = self.get_history()

        if not history:
            return {
                "total_scans": 0,
                "total_issues_found": 0,
                "severity_summary": {},
                "scan_types": {},
                "latest_scan": None,
            }

        total_issues = sum(int(record.get("total_issues", 0)) for record in history)

        severity_summary: Dict[str, int] = {}
        for level in SeverityLevel:
            severity_summary[level.name] = sum(
                int(record.get("severity_counts", {}).get(level.name, 0))
                for record in history
            )

        scan_types: Dict[str, int] = {}
        for record in history:
            scan_type = str(record.get("scan_type", "unknown"))
            scan_types[scan_type] = scan_types.get(scan_type, 0) + 1

        return {
            "total_scans": len(history),
            "total_issues_found": total_issues,
            "severity_summary": severity_summary,
            "scan_types": scan_types,
            "latest_scan": history[0] if history else None,
        }

    def clear_history(self) -> None:
        """Clear all stored scan history records."""
        if self.history_file.exists():
            try:
                self.history_file.unlink()
            except OSError:
                pass

    @staticmethod
    def _count_by_severity(issues: List[Dict[str, Any]]) -> Dict[SeverityLevel, int]:
        """Count issues grouped by severity level.

        Args:
            issues: List of issue dictionaries.

        Returns:
            Dictionary mapping SeverityLevel to count.
        """
        counts = {level: 0 for level in SeverityLevel}

        for issue in issues:
            severity = get_issue_severity(issue)
            counts[severity] += 1

        return counts

    @staticmethod
    def _summarize_issues(issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Summarize issues for audit history without storing sensitive secret values.

        Args:
            issues: List of issue dictionaries.

        Returns:
            List of summarized issue dictionaries.
        """
        return [
            {
                "matcher": issue.get("matcher"),
                "source": issue.get("source"),
                "line": issue.get("line"),
                "confidence": issue.get("confidence"),
            }
            for issue in issues
        ]
