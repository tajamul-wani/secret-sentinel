"""History and audit logging module for tracking scan results over time."""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from .risk_scoring import SeverityLevel


class ScanHistory:
    """Manages scan history and statistics."""
    
    HISTORY_DIR = ".secret-sentinel"
    HISTORY_FILE = "scan_history.jsonl"  # JSON Lines format for easy appending
    
    def __init__(self, repo_root: Optional[str] = None):
        """Initialize history manager.
        
        Args:
            repo_root: Root directory of the repository. Uses cwd if not provided.
        """
        self.repo_root = repo_root or os.getcwd()
        self.history_dir = Path(self.repo_root) / self.HISTORY_DIR
        self.history_file = self.history_dir / self.HISTORY_FILE
    
    def ensure_directory(self) -> None:
        """Create history directory if it doesn't exist."""
        self.history_dir.mkdir(exist_ok=True)
    
    def record_scan(
        self,
        issues: List[Dict],
        scan_type: str = "manual",
        status: str = "completed"
    ) -> None:
        """Record a scan in history.
        
        Args:
            issues: List of detected issues
            scan_type: Type of scan ('staged', 'manual', 'hook')
            status: Status of the scan ('completed', 'blocked', 'error')
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
        
        self.ensure_directory()
        with open(self.history_file, "a") as f:
            f.write(json.dumps(record) + "\n")
    
    def get_history(self, limit: Optional[int] = None) -> List[Dict]:
        """Get scan history.
        
        Args:
            limit: Maximum number of records to return. None for all records.
            
        Returns:
            List of scan records, newest first
        """
        if not self.history_file.exists():
            return []
        
        records = []
        with open(self.history_file, "r") as f:
            for line in f:
                if line.strip():
                    records.append(json.loads(line))
        
        # Return newest first
        records.reverse()
        
        if limit:
            records = records[:limit]
        
        return records
    
    def get_statistics(self) -> Dict:
        """Get aggregated statistics from scan history.
        
        Returns:
            Dictionary with statistics about scans
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
        
        total_issues = sum(record.get("total_issues", 0) for record in history)
        
        # Aggregate severity counts
        severity_summary = {}
        for level in SeverityLevel:
            severity_summary[level.name] = sum(
                record.get("severity_counts", {}).get(level.name, 0)
                for record in history
            )
        
        # Count by scan type
        scan_types = {}
        for record in history:
            scan_type = record.get("scan_type", "unknown")
            scan_types[scan_type] = scan_types.get(scan_type, 0) + 1
        
        return {
            "total_scans": len(history),
            "total_issues_found": total_issues,
            "severity_summary": severity_summary,
            "scan_types": scan_types,
            "latest_scan": history[0] if history else None,
        }
    
    def clear_history(self) -> None:
        """Clear all scan history."""
        if self.history_file.exists():
            self.history_file.unlink()
    
    @staticmethod
    def _count_by_severity(issues: List[Dict]) -> Dict[SeverityLevel, int]:
        """Count issues by severity level.
        
        Args:
            issues: List of issue dictionaries
            
        Returns:
            Dictionary mapping severity level to count
        """
        from .risk_scoring import get_risk_score
        
        counts = {level: 0 for level in SeverityLevel}
        
        for issue in issues:
            matcher = issue.get("matcher", "High entropy string")
            severity = get_risk_score(matcher)
            counts[severity] += 1
        
        return counts
    
    @staticmethod
    def _summarize_issues(issues: List[Dict]) -> List[Dict]:
        """Summarize issues for history (don't store full secret values).
        
        Args:
            issues: List of issue dictionaries
            
        Returns:
            List of summarized issue dictionaries
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
