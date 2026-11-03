"""Output formatters for Secret Sentinel scan results (Text, JSON, SARIF)."""

import json
from typing import Any, Dict, List, Optional

from .remediation import get_remediation
from .risk_scoring import SeverityLevel, calculate_overall_severity, get_issue_severity
from .utils import sanitize_snippet


_DETECTION_EXPLANATIONS = {
    "pattern": ("pattern", "A built-in secret pattern matched."),
    "custom-pattern": ("custom-pattern", "A configured custom rule matched."),
    "entropy": (
        "entropy",
        "A secret-related keyword appeared beside a high-entropy string.",
    ),
}
_CONFIDENCE_LEVELS = {"high", "medium", "low"}


def _get_detection_details(issue: Dict[str, Any]) -> tuple[str, str]:
    """Return a static, secret-free detection reason and explanation."""
    reason = issue.get("reason")
    if isinstance(reason, str):
        details = _DETECTION_EXPLANATIONS.get(reason)
        if details is not None:
            return details
    return "unknown", "A configured detector identified a potential secret."


def _get_confidence(issue: Dict[str, Any]) -> str:
    """Return a supported confidence label, or a safe unspecified value."""
    confidence = issue.get("confidence")
    if isinstance(confidence, str) and confidence.lower() in _CONFIDENCE_LEVELS:
        return confidence.lower()
    return "not specified"


def format_text(
    issues: List[Dict[str, Any]],
    fail_on: Optional[SeverityLevel] = None,
    baseline_suppressed: int = 0,
) -> str:
    """Format scan issues into human-readable text.

    Args:
        issues: List of detected issues.
        fail_on: Optional minimum severity level required to block.

    Returns:
        Formatted summary string.
    """
    if not issues:
        message = "All clear! No potential secrets found."
        if baseline_suppressed:
            message += f" ({baseline_suppressed} baseline finding(s) ignored)."
        return message

    severity_counts = {severity: 0 for severity in SeverityLevel}
    for issue in issues:
        severity_counts[get_issue_severity(issue)] += 1

    lines = [f"Detected potential secrets ({len(issues)}):"]
    lines.append(
        "Severity summary: "
        + ", ".join(
            f"{severity.name}: {count}"
            for severity, count in severity_counts.items()
            if count
        )
    )
    lines.append(
        "Next: verify each finding; revoke or rotate any real credential first, "
        "then investigate provider activity."
    )
    lines.append(
        "Possible false positive? Prefer a line-level ignore with a reason and "
        "expiry; avoid broad path exclusions."
    )

    ordered_issues = sorted(
        issues,
        key=lambda issue: get_issue_severity(issue).value,
        reverse=True,
    )
    for issue in ordered_issues:
        severity = get_issue_severity(issue)
        raw_snippet = str(issue.get("snippet", ""))
        secret_val = str(issue.get("value", ""))
        safe_snippet = sanitize_snippet(raw_snippet, secret_val)
        entry = (
            f"[{severity.name}] {issue['source']}:{issue['line']} "
            f"[{issue['matcher']}] - {safe_snippet}"
        )
        if issue.get("entropy") is not None:
            entry += f" (entropy={issue['entropy']})"
        if issue.get("commit"):
            entry += f" (commit {str(issue['commit'])[:12]})"
        lines.append(entry)
        _, explanation = _get_detection_details(issue)
        lines.append(
            f"  Why flagged: {explanation} "
            f"Confidence: {_get_confidence(issue)}."
        )
        lines.extend(
            f"  Remediation: {step}"
            for step in get_remediation(str(issue.get("matcher", "")))
        )

    if baseline_suppressed:
        lines.append(f"Baseline findings ignored: {baseline_suppressed}")

    overall_severity = calculate_overall_severity(issues)
    lines.append(f"Overall severity: {overall_severity}")

    threshold = fail_on or SeverityLevel.LOW
    if overall_severity.value >= threshold.value:
        lines.append("Commit blocked: secret-sentinel detected potential hardcoded secrets.")
    else:
        lines.append(
            f"Scan passed with warnings: detected issues are below failure threshold ({threshold.name})."
        )
    return "\n".join(lines)


def format_json(
    issues: List[Dict[str, Any]],
    fail_on: Optional[SeverityLevel] = None,
    baseline_suppressed: int = 0,
) -> str:
    """Format scan issues into machine-readable JSON without leaking credentials.

    Args:
        issues: List of detected issues.
        fail_on: Optional minimum severity level required to block.

    Returns:
        Indented JSON string.
    """
    overall_severity = calculate_overall_severity(issues)
    threshold = fail_on or SeverityLevel.LOW

    if not issues:
        status = "passed"
    elif overall_severity.value >= threshold.value:
        status = "blocked"
    else:
        status = "warning"

    sanitized_issues: List[Dict[str, Any]] = []
    for issue in issues:
        raw_snippet = str(issue.get("snippet", ""))
        secret_val = str(issue.get("value", ""))
        safe_snippet = sanitize_snippet(raw_snippet, secret_val)
        reason, explanation = _get_detection_details(issue)

        item = {
            "source": issue.get("source"),
            "line": issue.get("line"),
            "matcher": issue.get("matcher"),
            "snippet": safe_snippet,
            "confidence": _get_confidence(issue),
            "severity": issue.get("severity"),
            "reason": reason,
            "explanation": explanation,
        }
        if issue.get("entropy") is not None:
            item["entropy"] = issue.get("entropy")
        if issue.get("commit"):
            item["commit"] = issue.get("commit")
        item["remediation"] = get_remediation(str(issue.get("matcher", "")))
        sanitized_issues.append(item)

    report = {
        "status": status,
        "total_issues": len(issues),
        "overall_severity": overall_severity.name,
        "fail_on": threshold.name,
        "baseline_suppressed": baseline_suppressed,
        "issues": sanitized_issues,
    }
    return json.dumps(report, indent=2)


def format_sarif(
    issues: List[Dict[str, Any]],
    repo_root: Optional[str] = None,
    baseline_suppressed: int = 0,
) -> str:
    """Format scan issues into SARIF v2.1.0 format for GitHub Code Scanning.

    Args:
        issues: List of detected issues.
        repo_root: Optional repository root path.

    Returns:
        SARIF formatted JSON string.
    """
    rules_dict: Dict[str, Dict[str, Any]] = {}
    sarif_results: List[Dict[str, Any]] = []

    for issue in issues:
        rule_id = str(issue.get("matcher", "SecretDetection"))
        severity = get_issue_severity(issue).name
        sarif_level = "error" if severity in ("CRITICAL", "HIGH") else "warning"

        if rule_id not in rules_dict:
            rules_dict[rule_id] = {
                "id": rule_id,
                "name": rule_id.replace(" ", ""),
                "shortDescription": {
                    "text": f"Potential {rule_id} detected in source code"
                },
                "defaultConfiguration": {
                    "level": sarif_level
                },
            }

        raw_snippet = str(issue.get("snippet", ""))
        secret_val = str(issue.get("value", ""))
        safe_snippet = sanitize_snippet(raw_snippet, secret_val)
        reason, explanation = _get_detection_details(issue)
        confidence = _get_confidence(issue)

        result = {
            "ruleId": rule_id,
            "level": sarif_level,
            "message": {
                "text": (
                    f"Potential {rule_id} found: {safe_snippet} "
                    f"{explanation} Confidence: {confidence}."
                )
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": str(issue.get("source", "")),
                            "uriBaseId": "%SRCROOT%"
                        },
                        "region": {
                            "startLine": int(issue.get("line", 1))
                        }
                    }
                }
            ]
        }
        result["properties"] = {
            "confidence": confidence,
            "reason": reason,
            "explanation": explanation,
        }
        if issue.get("commit"):
            result["properties"]["commit"] = issue["commit"]
        result["properties"]["remediation"] = get_remediation(rule_id)
        sarif_results.append(result)

    sarif_log = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "secret-sentinel",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/tajamul-wani/secret-sentinel",
                        "rules": list(rules_dict.values())
                    }
                },
                "results": sarif_results
            }
        ]
    }
    if baseline_suppressed:
        sarif_log["runs"][0]["properties"] = {
            "baselineSuppressed": baseline_suppressed
        }
    return json.dumps(sarif_log, indent=2)
