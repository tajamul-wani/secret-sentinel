"""Output formatters for Secret Sentinel scan results (Text, JSON, SARIF)."""

import json
from typing import Any, Dict, List, Optional

from .risk_scoring import SeverityLevel, calculate_overall_severity
from .utils import sanitize_snippet


def format_text(issues: List[Dict[str, Any]]) -> str:
    """Format scan issues into human-readable text.

    Args:
        issues: List of detected issues.

    Returns:
        Formatted summary string.
    """
    if not issues:
        return "secret-sentinel scan passed."

    lines = [f"Detected potential secrets ({len(issues)}):"]
    for issue in issues:
        raw_snippet = str(issue.get("snippet", ""))
        secret_val = str(issue.get("value", ""))
        safe_snippet = sanitize_snippet(raw_snippet, secret_val)
        entry = f"{issue['source']}:{issue['line']} [{issue['matcher']}] - {safe_snippet}"
        if issue.get("entropy") is not None:
            entry += f" (entropy={issue['entropy']})"
        lines.append(entry)

    overall_severity = calculate_overall_severity(issues)
    lines.append(f"Overall severity: {overall_severity}")
    lines.append("Commit blocked: secret-sentinel detected potential hardcoded secrets.")
    return "\n".join(lines)


def format_json(issues: List[Dict[str, Any]]) -> str:
    """Format scan issues into machine-readable JSON without leaking credentials.

    Args:
        issues: List of detected issues.

    Returns:
        Indented JSON string.
    """
    overall_severity = calculate_overall_severity(issues)
    sanitized_issues: List[Dict[str, Any]] = []

    for issue in issues:
        raw_snippet = str(issue.get("snippet", ""))
        secret_val = str(issue.get("value", ""))
        safe_snippet = sanitize_snippet(raw_snippet, secret_val)

        item = {
            "source": issue.get("source"),
            "line": issue.get("line"),
            "matcher": issue.get("matcher"),
            "snippet": safe_snippet,
            "confidence": issue.get("confidence"),
            "severity": issue.get("severity"),
        }
        if issue.get("entropy") is not None:
            item["entropy"] = issue.get("entropy")
        sanitized_issues.append(item)

    report = {
        "status": "blocked" if issues else "passed",
        "total_issues": len(issues),
        "overall_severity": overall_severity.name,
        "issues": sanitized_issues,
    }
    return json.dumps(report, indent=2)


def format_sarif(issues: List[Dict[str, Any]], repo_root: Optional[str] = None) -> str:
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
        severity = str(issue.get("severity", "MEDIUM")).upper()
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

        sarif_results.append({
            "ruleId": rule_id,
            "level": sarif_level,
            "message": {
                "text": f"Potential {rule_id} found: {safe_snippet}"
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
        })

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
    return json.dumps(sarif_log, indent=2)

