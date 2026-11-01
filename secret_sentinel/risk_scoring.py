"""Risk scoring module for assigning severity levels to detected secrets."""

from enum import Enum
from typing import Any, Dict, List


class SeverityLevel(Enum):
    """Severity levels for secrets."""

    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1

    def __str__(self) -> str:
        """Return severity name."""
        return self.name


# Risk scores assigned to each secret type
SECRET_RISK_SCORES: Dict[str, SeverityLevel] = {
    "AWS Secret Access Key": SeverityLevel.CRITICAL,
    "Google API Key": SeverityLevel.CRITICAL,
    "Stripe API Key": SeverityLevel.CRITICAL,
    "GitHub Token": SeverityLevel.CRITICAL,
    "Slack Token": SeverityLevel.CRITICAL,
    "Twilio Secret Key": SeverityLevel.CRITICAL,
    "Private Key": SeverityLevel.CRITICAL,
    "Database Connection URI": SeverityLevel.CRITICAL,
    "OpenAI API Key": SeverityLevel.CRITICAL,
    "Anthropic API Key": SeverityLevel.CRITICAL,
    "HuggingFace Token": SeverityLevel.CRITICAL,
    "PyPI API Token": SeverityLevel.CRITICAL,
    "NPM Access Token": SeverityLevel.CRITICAL,
    "JWT": SeverityLevel.HIGH,
    "Generic Secret Assignment": SeverityLevel.HIGH,
    "High entropy string": SeverityLevel.MEDIUM,
}


def get_risk_score(matcher: str) -> SeverityLevel:
    """Get risk score for a secret type.

    Args:
        matcher: The name of the secret pattern/matcher.

    Returns:
        SeverityLevel for matched secret type, defaults to MEDIUM if unknown.
    """
    return SECRET_RISK_SCORES.get(matcher, SeverityLevel.MEDIUM)


def get_issue_severity(issue: Dict[str, Any]) -> SeverityLevel:
    """Return a valid explicit issue severity or the built-in matcher score."""
    severity_name = issue.get("severity")
    if isinstance(severity_name, str):
        try:
            return SeverityLevel[severity_name.upper()]
        except KeyError:
            pass
    return get_risk_score(str(issue.get("matcher", "High entropy string")))


def calculate_overall_severity(issues: List[Dict[str, Any]]) -> SeverityLevel:
    """Calculate the overall severity level for a set of issues.

    Args:
        issues: List of issue dictionaries with 'matcher' field.

    Returns:
        The highest severity level found, or LOW if no issues.
    """
    if not issues:
        return SeverityLevel.LOW

    max_severity = SeverityLevel.LOW
    for issue in issues:
        severity = get_issue_severity(issue)
        if severity.value > max_severity.value:
            max_severity = severity

    return max_severity
