"""Provider-specific response guidance for detected secret types."""


_DEFAULT_GUIDANCE = (
    "If this value is a real credential, revoke or rotate it with its issuer.",
    "Check provider activity and access logs for unexpected use.",
    "Move the replacement into a secrets manager or environment configuration.",
    "After revocation, remove the exposed value from repository history if needed.",
)

_REMEDIATION: dict[str, tuple[str, ...]] = {
    "AWS Access Key ID": (
        (
            "An access key ID alone cannot authenticate requests; "
            "check whether its matching secret access key was also exposed."
        ),
        (
            "Review CloudTrail and IAM activity for unexpected use of the "
            "associated identity."
        ),
        (
            "If the matching secret access key was exposed, deactivate the pair "
            "and issue a replacement."
        ),
    ),
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
    "PuTTY Private Key": (
        "Treat the PuTTY private key (.ppk) as compromised; revoke the corresponding public key on all SSH servers.",
        "Remove the .ppk file from repository history and ensure SSH keys are never committed.",
        "Generate a replacement key pair and update authorized_keys files on target hosts.",
        "Store private keys in a secure local SSH agent or secrets manager.",
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
    "GitLab Token": (
        "Revoke the token in GitLab User Settings / Access Tokens and issue a replacement with minimal scopes.",
        "Review GitLab security events and audit logs for unexpected repository or API activity.",
        "Update CI/CD variables and integrations to load the replacement from a secrets manager.",
        "After revocation, remove the exposed value from repository history if needed.",
    ),
    "SendGrid API Key": (
        "Revoke the API key in the Twilio SendGrid Console and create a replacement with restricted permissions.",
        "Review SendGrid activity feed and mail delivery logs for unauthorized sending.",
        "Update email delivery services to load the replacement from environment secrets.",
        "After revocation, remove the exposed key from repository history if needed.",
    ),
    "Azure Storage Account Key": (
        "Regenerate the affected access key in Azure Portal and update applications with Azure Key Vault.",
        "Review Azure Monitor and Storage audit logs for unauthorized access patterns.",
        "Consider migrating to Microsoft Entra ID (Azure AD) authentication to avoid shared access keys.",
        "After regeneration, remove the exposed key from repository history if needed.",
    ),
    "Google OAuth Client Secret": (
        "Reset or delete the OAuth client secret in Google Cloud Console under APIs & Services > Credentials.",
        "Review OAuth consent screen activity and connected third-party applications for anomalies.",
        "Update client applications to retrieve secrets securely from server-side configuration.",
        "After rotation, remove the exposed secret from repository history if needed.",
    ),
    "Shopify Access Token": (
        "Revoke the access token in Shopify Partner Dashboard or Store Admin and reinstall or regenerate credentials.",
        "Review Shopify admin API logs and order/customer activity for unauthorized access.",
        "Store the replacement access token in secure environment variables or a secrets manager.",
        "After revocation, remove the exposed token from repository history if needed.",
    ),
    "DigitalOcean Token": (
        "Revoke the personal access token in DigitalOcean Control Panel under API settings.",
        "Review DigitalOcean audit logs and droplet/resource changes for unexpected actions.",
        "Issue a scoped replacement token and store it in a secrets manager.",
        "After revocation, remove the exposed token from repository history if needed.",
    ),
    "Telegram Bot Token": (
        "Revoke and regenerate the bot token using BotFather (/revoke command) in Telegram.",
        "Review bot commands, webhooks, and chat logs for unexpected activity.",
        "Deploy the replacement bot token through secure environment variables.",
        "After revocation, remove the exposed token from repository history if needed.",
    ),
    "Databricks Token": (
        "Revoke the personal access token in Databricks User Settings and issue a replacement with limited lifetime.",
        "Review workspace audit logs and compute cluster activity for unexpected usage.",
        "Update automated pipelines to load the replacement token from secrets storage.",
        "After revocation, remove the exposed token from repository history if needed.",
    ),
    "Mailchimp API Key": (
        "Revoke the API key in Mailchimp Account Settings > Extras > API keys and generate a new key.",
        "Review campaign history and audience changes for unauthorized modifications.",
        "Update marketing automations to load the replacement key securely.",
        "After revocation, remove the exposed key from repository history if needed.",
    ),
    "Slack Webhook URL": (
        "Delete the exposed webhook in Slack App Directory or App Management and create a new incoming webhook.",
        "Review channel message history for unexpected automated postings.",
        "Store the replacement webhook URL in protected environment variables.",
        "After deletion, remove the exposed webhook URL from repository history if needed.",
    ),
    "Discord Bot Token": (
        "Reset the bot token in Discord Developer Portal under Applications > Bot immediately.",
        "Review bot audit logs, guild memberships, and message dispatches for unauthorized actions.",
        "Deploy the replacement bot token via environment variables or a secrets manager.",
        "After resetting, remove the exposed token from repository history if needed.",
    ),
    "Discord Webhook URL": (
        "Delete the exposed webhook in Discord Channel Settings > Integrations > Webhooks and generate a new URL.",
        "Review channel message history for unauthorized automated posts.",
        "Store the new webhook URL in environment configuration, never hardcoded in source files.",
        "After deletion, remove the exposed webhook URL from repository history if needed.",
    ),
    "Groq API Key": (
        "Revoke the API key in Groq Console under API Keys and generate a replacement.",
        "Review Groq request logs and credit consumption for unexpected inference calls.",
        "Update applications to load the replacement key from environment variables or a secrets manager.",
        "After revocation, remove the exposed key from repository history if needed.",
    ),
    "Postman API Key": (
        "Revoke the API key in Postman Account Settings > API Keys and generate a new key.",
        "Review Postman workspace activity and collection audit history for unauthorized changes.",
        "Update collection runners and CI/CD pipelines to load the replacement key securely.",
        "After revocation, remove the exposed key from repository history if needed.",
    ),
    "Square Access Token": (
        "Revoke or regenerate the OAuth access token or application secret in Square Developer Dashboard.",
        "Review payment logs, merchant transactions, and account activity for unexpected operations.",
        "Update point-of-sale or e-commerce integrations with the replacement token from secrets storage.",
        "After revocation, remove the exposed token from repository history if needed.",
    ),
    "Sentry Token": (
        "Revoke the auth token in Sentry Settings > Developer Settings > Auth Tokens.",
        "Review organization audit logs and project event submissions for unauthorized activity.",
        "Update CI/CD build scripts and CLI tools with a newly scoped auth token.",
        "After revocation, remove the exposed token from repository history if needed.",
    ),
    "Netrc Password": (
        "Change the password for the affected machine entry and restrict filesystem permissions on .netrc (chmod 600).",
        "Review service logs for unauthorized logins using the compromised credentials.",
        "Prefer SSH keys or scoped personal access tokens over plaintext passwords in .netrc.",
        "Remove the plaintext credentials from repository tracking immediately.",
    ),
    "PostgreSQL Password File": (
        "Change the PostgreSQL user password on the database server immediately.",
        "Restrict filesystem permissions on .pgpass (chmod 600) and verify connecting client hosts.",
        "Review PostgreSQL authentication and connection logs for unexpected client addresses.",
        "Remove the .pgpass entry from version control immediately.",
    ),
    "Docker Registry Auth": (
        "Change the registry password or revoke the personal access token associated with the encoded Docker auth entry.",
        "Review registry image pull/push logs for unauthorized image uploads or downloads.",
        "Use docker credential helpers or short-lived CI registry tokens instead of persistent config files.",
        "Remove the encoded auth entry from repository tracking.",
    ),
    "Password Assignment": (
        "Change the hardcoded password immediately across all services and databases where it was configured.",
        "Review authentication logs for unauthorized access during the exposure window.",
        "Store the replacement password in an approved secrets manager or protected environment variable.",
        "After rotation, remove the exposed password from repository history if needed.",
    ),
    "Generic Secret Assignment": _DEFAULT_GUIDANCE,
    "High entropy string": _DEFAULT_GUIDANCE,
}


def get_remediation(matcher: str) -> list[str]:
    """Return safe response steps for a detected matcher."""
    return list(_REMEDIATION.get(matcher, _DEFAULT_GUIDANCE))


def get_remediation_preview(matcher: str) -> str:
    """Return a secret-free, manual remediation preview for a finding."""
    if matcher == "AWS Access Key ID":
        return (
            "Check for exposure of the matching secret access key; an access key "
            "ID alone is not an authenticator. No source files are changed."
        )
    if matcher == "Private Key":
        return (
            "After replacing the key, remove the private-key block from source and "
            "load key material through an approved key-management mechanism. "
            "No source files are changed."
        )
    return (
        "After rotation, replace the hardcoded value with a runtime lookup from an "
        "environment variable or approved secrets manager. Adapt the lookup to "
        "the source language and review it before applying. No source files are changed."
    )
