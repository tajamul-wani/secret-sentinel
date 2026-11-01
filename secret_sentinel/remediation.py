"""Provider-specific response guidance for detected secret types."""

from typing import Dict, List, Tuple


_DEFAULT_GUIDANCE = (
    "If this value is a real credential, revoke or rotate it with its issuer.",
    "Check provider activity and access logs for unexpected use.",
    "Move the replacement into a secrets manager or environment configuration.",
    "After revocation, remove the exposed value from repository history if needed.",
)

_REMEDIATION: Dict[str, Tuple[str, ...]] = {
    "AWS Secret Access Key": (
        "Deactivate the access key in IAM and issue a replacement for the affected identity.",
        "Review CloudTrail and IAM activity for unexpected use; apply least-privilege permissions.",
        "Update workloads to use the replacement through an AWS secrets manager or role-based credentials.",
        "After deactivation, remove the exposed value from repository history if needed.",
    ),
    "Google API Key": (
        "Restrict or delete the key in Google Cloud Console, then issue a replacement.",
        "Review API usage and billing for unexpected activity; apply API and application restrictions.",
        "Update applications to load the replacement from a secrets manager.",
        "After disabling the key, remove the exposed value from repository history if needed.",
    ),
    "Stripe API Key": (
        "Roll or revoke the key in the Stripe Dashboard and issue a replacement.",
        "Review Stripe request logs and account activity for unexpected use.",
        "Update integrations to load the replacement from a secrets manager.",
        "After revocation, remove the exposed value from repository history if needed.",
    ),
    "GitHub Token": (
        "Revoke the token in GitHub settings and create a replacement with only the required scopes.",
        "Review account security logs and token activity for unexpected use.",
        "Update automation to load the replacement from a GitHub Actions secret or secrets manager.",
        "After revocation, remove the exposed value from repository history if needed.",
    ),
    "Slack Token": (
        "Revoke or rotate the token in Slack app settings.",
        "Review audit and app activity logs for unexpected access or messages.",
        "Update integrations to load the replacement from a secrets manager.",
        "After revocation, remove the exposed value from repository history if needed.",
    ),
    "Twilio Secret Key": (
        "Revoke or rotate the API key or Auth Token in the Twilio Console.",
        "Review usage and access logs for unexpected calls, messages, or charges.",
        "Update services to load the replacement from a secrets manager.",
        "After revocation, remove the exposed value from repository history if needed.",
    ),
    "Private Key": (
        "Treat the corresponding private key as compromised; revoke or replace its certificate or key pair.",
        "Review systems and access logs that trust the key, and remove the old public key from authorized locations.",
        "Deploy the replacement key through your approved key-management process.",
        "After revocation, remove the exposed key material from repository history if needed.",
    ),
    "Database Connection URI": (
        "Rotate the database user's password or credential and invalidate existing sessions if supported.",
        "Review database authentication and query logs for unexpected access.",
        "Update applications to load the replacement URI from a secrets manager.",
        "After rotation, remove the exposed URI from repository history if needed.",
    ),
    "OpenAI API Key": (
        "Revoke the key in the OpenAI platform and create a replacement.",
        "Review API usage and billing for unexpected activity.",
        "Update applications to load the replacement from a secrets manager.",
        "After revocation, remove the exposed value from repository history if needed.",
    ),
    "Anthropic API Key": (
        "Revoke the key in the Anthropic Console and create a replacement.",
        "Review workspace usage and billing for unexpected activity.",
        "Update applications to load the replacement from a secrets manager.",
        "After revocation, remove the exposed value from repository history if needed.",
    ),
    "HuggingFace Token": (
        "Revoke the token in Hugging Face account settings and issue a replacement with minimal permissions.",
        "Review account and repository activity for unexpected use.",
        "Update tools to load the replacement from a secrets manager.",
        "After revocation, remove the exposed value from repository history if needed.",
    ),
    "PyPI API Token": (
        "Revoke the token in PyPI account settings and create a replacement scoped to required projects.",
        "Review project releases and account activity for unexpected changes.",
        "Update publishing automation to load the replacement from a CI secret.",
        "After revocation, remove the exposed value from repository history if needed.",
    ),
    "NPM Access Token": (
        "Revoke the token in npm account settings and create a replacement with minimal access.",
        "Review package and account activity for unexpected publishing or changes.",
        "Update publishing automation to load the replacement from a CI secret.",
        "After revocation, remove the exposed value from repository history if needed.",
    ),
    "JWT": (
        "Invalidate the token if possible; otherwise rotate the signing key so issued tokens are rejected.",
        "Review authentication logs and affected sessions for unexpected use.",
        "Store replacement signing keys in a secrets manager and enforce appropriate token expiry.",
        "After invalidation, remove the exposed token or key from repository history if needed.",
    ),
    "Generic Secret Assignment": _DEFAULT_GUIDANCE,
    "High entropy string": _DEFAULT_GUIDANCE,
}


def get_remediation(matcher: str) -> List[str]:
    """Return safe response steps for a detected matcher."""
    return list(_REMEDIATION.get(matcher, _DEFAULT_GUIDANCE))
