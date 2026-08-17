"""Tests for risk scoring and history modules."""

import json
import tempfile
from pathlib import Path
from unittest import TestCase

from secret_sentinel.risk_scoring import (
    SeverityLevel,
    get_risk_score,
    calculate_overall_severity,
)
from secret_sentinel.history import ScanHistory


class TestRiskScoring(TestCase):
    """Tests for risk scoring functionality."""

    def test_get_risk_score_critical(self):
        """Test that critical secrets are scored as CRITICAL."""
        assert get_risk_score("AWS Secret Access Key") == SeverityLevel.CRITICAL
        assert get_risk_score("GitHub Token") == SeverityLevel.CRITICAL

    def test_get_risk_score_high(self):
        """Test that high-risk secrets are scored as HIGH."""
        assert get_risk_score("JWT") == SeverityLevel.HIGH
        assert get_risk_score("Generic Secret Assignment") == SeverityLevel.HIGH

    def test_get_risk_score_medium(self):
        """Test that entropy strings are scored as MEDIUM."""
        assert get_risk_score("High entropy string") == SeverityLevel.MEDIUM

    def test_get_risk_score_unknown(self):
        """Test that unknown types default to MEDIUM."""
        assert get_risk_score("Unknown Type") == SeverityLevel.MEDIUM

    def test_calculate_overall_severity_empty(self):
        """Test overall severity with no issues."""
        assert calculate_overall_severity([]) == SeverityLevel.LOW

    def test_calculate_overall_severity_critical(self):
        """Test overall severity with CRITICAL issues."""
        issues = [
            {"matcher": "AWS Secret Access Key"},
            {"matcher": "High entropy string"},
        ]
        assert calculate_overall_severity(issues) == SeverityLevel.CRITICAL

    def test_calculate_overall_severity_high(self):
        """Test overall severity with HIGH issues only."""
        issues = [
            {"matcher": "JWT"},
            {"matcher": "High entropy string"},
        ]
        assert calculate_overall_severity(issues) == SeverityLevel.HIGH


class TestScanHistory(TestCase):
    """Tests for scan history functionality."""

    def setUp(self):
        """Set up temporary directory for tests."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.repo_root = self.temp_dir.name
        self.history = ScanHistory(self.repo_root)

    def tearDown(self):
        """Clean up temporary directory."""
        self.temp_dir.cleanup()

    def test_record_scan(self):
        """Test recording a scan."""
        issues = [
            {"matcher": "AWS Secret Access Key", "source": "app.py", "line": 10},
            {"matcher": "High entropy string", "source": "app.py", "line": 20},
        ]
        self.history.record_scan(issues, scan_type="manual")

        # Verify file was created
        assert self.history.history_file.exists()

    def test_get_history_empty(self):
        """Test getting history when none exists."""
        history = self.history.get_history()
        assert history == []

    def test_get_history_with_records(self):
        """Test getting history with records."""
        issues = [{"matcher": "AWS Secret Access Key"}]
        self.history.record_scan(issues, scan_type="staged")

        history = self.history.get_history()
        assert len(history) == 1
        assert history[0]["scan_type"] == "staged"
        assert history[0]["total_issues"] == 1

    def test_get_statistics(self):
        """Test getting statistics."""
        issues1 = [
            {"matcher": "AWS Secret Access Key"},
            {"matcher": "GitHub Token"},
        ]
        issues2 = [{"matcher": "High entropy string"}]

        self.history.record_scan(issues1, scan_type="staged")
        self.history.record_scan(issues2, scan_type="manual")

        stats = self.history.get_statistics()
        assert stats["total_scans"] == 2
        assert stats["total_issues_found"] == 3
        assert stats["severity_summary"]["CRITICAL"] == 2
        assert stats["severity_summary"]["MEDIUM"] == 1

    def test_clear_history(self):
        """Test clearing history."""
        issues = [{"matcher": "AWS Secret Access Key"}]
        self.history.record_scan(issues)

        assert self.history.history_file.exists()
        self.history.clear_history()
        assert not self.history.history_file.exists()


if __name__ == "__main__":
    import pytest

    pytest.main([__file__, "-v"])
