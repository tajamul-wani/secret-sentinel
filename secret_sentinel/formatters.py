"""Output formatters for Secret Sentinel scan results (Text, JSON, SARIF)."""

import json
from typing import Any

from .remediation import get_remediation, get_remediation_preview
from .risk_scoring import SeverityLevel, calculate_overall_severity, get_issue_severity
from .scanner import RULE_PACK_VERSION
from .utils import sanitize_snippet

_DETECTION_EXPLANATIONS = {
    "pattern": ("pattern", "A built-in secret pattern matched."),
    "custom-pattern": ("custom-pattern", "A configured custom rule matched."),
    "encoded-pattern": (
        "encoded-pattern",
        "A decoded value matched a built-in secret pattern.",
    ),
    "entropy": (
        "entropy",
        "A high-entropy string was assigned to a secret-related field.",
    ),
    "private-key-block": (
        "private-key-block",
        "A complete private-key block was found.",
    ),
    "private-key-header": (
        "private-key-header",
        "A private-key header was found without a complete block.",
    ),
}
_CONFIDENCE_LEVELS = {"high", "medium", "low"}


def _get_detection_details(issue: dict[str, Any]) -> tuple[str, str]:
    """Return a static, secret-free detection reason and explanation."""
    reason = issue.get("reason")
    if isinstance(reason, str):
        details = _DETECTION_EXPLANATIONS.get(reason)
        if details is not None:
            if (
                reason == "pattern"
                and issue.get("matcher") == "Generic Secret Assignment"
            ):
                return (
                    "pattern",
                    "A non-placeholder value was assigned to a secret-related field.",
                )
            return details
    return "unknown", "A configured detector identified a potential secret."


def _get_evidence(issue: dict[str, Any]) -> str:
    """Return a static explanation of the signal without exposing the value."""
    reason = issue.get("reason")
    if reason == "pattern":
        if issue.get("matcher") == "Generic Secret Assignment":
            return "Credential-like field assignment"
        return "Built-in credential format"
    evidence = {
        "custom-pattern": "Configured regular-expression rule",
        "encoded-pattern": "Base64-decoded credential format",
        "entropy": "High entropy in a secret-related field",
        "private-key-block": "Complete private-key block",
        "private-key-header": "Private-key header only",
    }
    return evidence.get(str(reason), "Unspecified detector signal")


def _get_confidence(issue: dict[str, Any]) -> str:
    """Return a supported confidence label, or a safe unspecified value."""
    confidence = issue.get("confidence")
    if isinstance(confidence, str) and confidence.lower() in _CONFIDENCE_LEVELS:
        return confidence.lower()
    return "not specified"


def format_text(
    issues: list[dict[str, Any]],
    fail_on: SeverityLevel | None = None,
    baseline_suppressed: int = 0,
    coverage: dict[str, int] | None = None,
) -> str:
    """Format scan issues into human-readable text.

    Args:
        issues: List of detected issues.
        fail_on: Optional minimum severity level required to block.

    Returns:
        Formatted summary string.
    """
    if not issues:
        incomplete = coverage is not None and (
            coverage.get("unreadable_paths", 0) > 0
            or coverage.get("missing_paths", 0) > 0
            or coverage.get("oversized_files", 0) > 0
        )
        message = (
            "Scan incomplete. No potential secrets were found in readable files."
            if incomplete
            else "All clear! No potential secrets found."
        )
        if baseline_suppressed:
            message += f" ({baseline_suppressed} baseline finding(s) ignored)."
        if coverage is not None:
            message += "\n" + _format_coverage(coverage)
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
        lines.append(f"  Evidence: {_get_evidence(issue)}.")
        lines.append(
            "  Suggested fix: "
            + get_remediation_preview(str(issue.get("matcher", "")))
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
    elif coverage is None or not (
        coverage.get("unreadable_paths", 0)
        or coverage.get("missing_paths", 0)
        or coverage.get("oversized_files", 0)
    ):
        lines.append(
            f"Scan passed with warnings: detected issues are below failure threshold ({threshold.name})."
        )
    if coverage is not None and (
        coverage.get("unreadable_paths", 0)
        or coverage.get("missing_paths", 0)
        or coverage.get("oversized_files", 0)
    ):
        lines.append("Scan incomplete: some requested paths could not be checked.")
    if coverage is not None:
        lines.append(_format_coverage(coverage))
    return "\n".join(lines)


def _format_coverage(coverage: dict[str, int]) -> str:
    """Format a scan coverage summary."""
    return (
        "Coverage: "
        f"{coverage.get('scanned_files', 0)} scanned, "
        f"{coverage.get('ignored_paths', 0)} ignored, "
        f"{coverage.get('binary_files', 0)} binary, "
        f"{coverage.get('unreadable_paths', 0)} unreadable, "
        f"{coverage.get('missing_paths', 0)} missing, "
        f"{coverage.get('oversized_files', 0)} oversized."
    )


def format_json(
    issues: list[dict[str, Any]],
    fail_on: SeverityLevel | None = None,
    baseline_suppressed: int = 0,
    coverage: dict[str, int] | None = None,
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

    incomplete = coverage is not None and (
        coverage.get("unreadable_paths", 0)
        or coverage.get("missing_paths", 0)
        or coverage.get("oversized_files", 0)
    )
    if incomplete:
        status = "incomplete"
    elif not issues:
        status = "passed"
    elif overall_severity.value >= threshold.value:
        status = "blocked"
    else:
        status = "warning"

    sanitized_issues: list[dict[str, Any]] = []
    for issue in issues:
        raw_snippet = str(issue.get("snippet", ""))
        secret_val = str(issue.get("value", ""))
        safe_snippet = sanitize_snippet(raw_snippet, secret_val)
        reason, explanation = _get_detection_details(issue)
        evidence = _get_evidence(issue)

        item = {
            "source": issue.get("source"),
            "line": issue.get("line"),
            "matcher": issue.get("matcher"),
            "snippet": safe_snippet,
            "confidence": _get_confidence(issue),
            "severity": issue.get("severity"),
            "reason": reason,
            "explanation": explanation,
            "evidence": evidence,
        }
        if issue.get("entropy") is not None:
            item["entropy"] = issue.get("entropy")
        if issue.get("commit"):
            item["commit"] = issue.get("commit")
        item["remediation"] = get_remediation(str(issue.get("matcher", "")))
        item["remediation_preview"] = get_remediation_preview(
            str(issue.get("matcher", ""))
        )
        sanitized_issues.append(item)

    report = {
        "status": status,
        "total_issues": len(issues),
        "overall_severity": overall_severity.name,
        "fail_on": threshold.name,
        "baseline_suppressed": baseline_suppressed,
        "rule_pack_version": RULE_PACK_VERSION,
        "issues": sanitized_issues,
    }
    if coverage is not None:
        report["coverage"] = coverage
        report["scan_complete"] = not (
            coverage.get("unreadable_paths", 0)
            or coverage.get("missing_paths", 0)
        )
    return json.dumps(report, indent=2)


def format_sarif(
    issues: list[dict[str, Any]],
    repo_root: str | None = None,
    baseline_suppressed: int = 0,
    coverage: dict[str, int] | None = None,
) -> str:
    """Format scan issues into SARIF v2.1.0 format for GitHub Code Scanning.

    Args:
        issues: List of detected issues.
        repo_root: Optional repository root path.

    Returns:
        SARIF formatted JSON string.
    """
    rules_dict: dict[str, dict[str, Any]] = {}
    sarif_results: list[dict[str, Any]] = []

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
        evidence = _get_evidence(issue)

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
            "evidence": evidence,
            "remediationPreview": get_remediation_preview(rule_id),
            "rulePackVersion": RULE_PACK_VERSION,
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
    run_properties: dict[str, Any] = {"rulePackVersion": RULE_PACK_VERSION}
    if baseline_suppressed:
        run_properties["baselineSuppressed"] = baseline_suppressed
    if coverage is not None:
        run_properties["coverage"] = coverage
        run_properties["scanComplete"] = not (
            coverage.get("unreadable_paths", 0)
            or coverage.get("missing_paths", 0)
        )
    sarif_log["runs"][0]["properties"] = run_properties
    return json.dumps(sarif_log, indent=2)


def format_suppression_audit_text(
    suppressions: list[dict[str, Any]],
) -> str:
    """Format suppression audit records as human-readable text."""
    if not suppressions:
        return "No inline suppression directives found."

    problem_count = sum(
        suppression.get("statuses") != ["active"]
        for suppression in suppressions
    )
    lines = ["Suppression audit"]
    for suppression in suppressions:
        statuses = suppression.get("statuses", [])
        status_text = ", ".join(
            str(status).replace("-", " ").upper() for status in statuses
        )
        line = f"{suppression.get('source', '')}:{suppression.get('line', '')}"
        target_line = suppression.get("target_line")
        if target_line is not None and target_line != suppression.get("line"):
            line += f" -> line {target_line}"
        lines.append(f"{line} [{status_text}]")

    if problem_count:
        lines.append(
            f"{problem_count} suppression(s) need review; "
            "remove obsolete directives or add a reason and future expiry."
        )
    else:
        lines.append(
            f"All {len(suppressions)} suppression(s) are documented and in use."
        )
    return "\n".join(lines)


def format_suppression_audit_json(
    suppressions: list[dict[str, Any]],
) -> str:
    """Format suppression audit records as secret-free JSON."""
    needs_review = sum(
        suppression.get("statuses") != ["active"]
        for suppression in suppressions
    )
    report = {
        "status": "review" if needs_review else "passed",
        "total_suppressions": len(suppressions),
        "needs_review": needs_review,
        "suppressions": [
            {
                "source": suppression.get("source"),
                "line": suppression.get("line"),
                "target_line": suppression.get("target_line"),
                "statuses": suppression.get("statuses", []),
            }
            for suppression in suppressions
        ],
    }
    return json.dumps(report, indent=2)


def format_suppression_audit_sarif(
    suppressions: list[dict[str, Any]],
) -> str:
    """Format suppression audit records as SARIF v2.1.0 diagnostics."""
    rules = [
        {
            "id": "suppression-active",
            "name": "ActiveSuppression",
            "shortDescription": {"text": "Documented active suppression"},
            "defaultConfiguration": {"level": "note"},
        },
        {
            "id": "suppression-review",
            "name": "SuppressionNeedsReview",
            "shortDescription": {"text": "Suppression needs review"},
            "defaultConfiguration": {"level": "warning"},
        },
    ]
    results: list[dict[str, Any]] = []
    for suppression in suppressions:
        statuses = suppression.get("statuses", [])
        needs_review = statuses != ["active"]
        status_text = ", ".join(
            str(status).replace("-", " ") for status in statuses
        )
        result: dict[str, Any] = {
            "ruleId": "suppression-review" if needs_review else "suppression-active",
            "level": "warning" if needs_review else "note",
            "message": {
                "text": (
                    f"Suppression needs review: {status_text}."
                    if needs_review
                    else "Suppression is documented and active."
                )
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": str(suppression.get("source", "")),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": int(suppression.get("line", 1))
                        },
                    }
                }
            ],
            "properties": {"statuses": statuses},
        }
        target_line = suppression.get("target_line")
        if target_line is not None:
            result["properties"]["targetLine"] = target_line
        results.append(result)

    sarif_log = {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
            "Schemata/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "secret-sentinel",
                        "version": "0.1.0",
                        "informationUri": (
                            "https://github.com/tajamul-wani/secret-sentinel"
                        ),
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif_log, indent=2)
