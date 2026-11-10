"""Labeled synthetic cases for scanner precision and recall regressions."""

import base64
import sys
import unittest
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from secret_sentinel.scanner import RULE_PACK_VERSION, scan_text

CORPUS_VERSION = 5


@dataclass(frozen=True)
class DetectionCase:
    """One labeled input for the scanner's small regression corpus."""

    name: str
    content: str
    should_detect: bool
    expected_matcher: str = ""
    source: str = ""


@dataclass(frozen=True)
class DetectionMetrics:
    """Finding-level confusion counts for the corpus or one detector."""

    true_positive: int = 0
    false_positive: int = 0
    false_negative: int = 0

    @property
    def precision(self) -> float | None:
        """Return precision, or None when there are no predicted findings."""
        predictions = self.true_positive + self.false_positive
        return self.true_positive / predictions if predictions else None

    @property
    def recall(self) -> float | None:
        """Return recall, or None when there are no expected findings."""
        expected = self.true_positive + self.false_negative
        return self.true_positive / expected if expected else None


def build_cases() -> list[DetectionCase]:
    """Build labeled examples across common formats and benign lookalikes."""
    aws_access_key = "AKIA" + "1234567890ABCDEF"
    aws_temporary_key = "ASIA" + "1234567890ABCDEF"
    aws_secret_key = "AbCd1234" * 5
    google_key = "AIza" + "AbCdEfGhIjKlMnOpQrStUvWxYz012345678"
    stripe_test_key = "sk_test_" + "123456789012345678901234"
    stripe_live_key = "sk_live_" + "123456789012345678901234"
    stripe_restricted_key = "rk_live_" + "123456789012345678901234"
    stripe_publishable_key = "pk_live_" + "123456789012345678901234"
    github_token = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz"
    slack_token = "xoxb-" + "1234567890" + "-" + "abcdefghij"
    slack_user_token = "xoxp-" + "abcdefghij" + "-" + "1234567890"
    twilio_key = "SK" + "1234567890abcdef" * 2
    database_password = "password" + "Example123"
    database_uri = "postgresql://app:" + database_password + "@db.example.com/app"
    mysql_uri = (
        "mysql://service:syntheticPassword123@db.example.test:3306/application"
    )
    redis_uri = (
        "redis://default:synthetic%40Password%3A123@cache.example.test:6379/0"
    )
    generic_token = "token_" + "0123456789abcdef01234567"
    openai_key = "sk-proj-" + "0123456789abcdefghijklmnopqrstuvwxyz"
    anthropic_key = "sk-ant-" + "0123456789abcdefghijklmnopqrstuvwxyz"
    huggingface_token = "hf_" + "1234567890abcdefghijklmnopqrstuvwx"
    pypi_token = (
        "pypi-AgEIcHlwaS5vcmc"
        + "1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdef"
    )
    npm_token = "npm_" + "1234567890abcdefghijklmnopqrstuvwxyz"
    service_secret = "svc_" + "a1b2c3d4e5f6g7h8i9j0k1l2"
    access_token = "tok_" + "a1b2c3d4e5f6g7h8i9j0k1l2"
    legacy_secret = "aB3dE5gH7jK9mP2rS4vX6zC8"
    high_entropy_value = "K9zXwQ7p.L2vM5yB8.tR4cE1aD3.fG6hJ0n"
    unrelated_entropy = "P8mQ2rV6xN4bK9sT1wC7dF3hJ5aL0eG"
    ssh_public_key = "ssh-ed25519 AAAA" + "a" * 40
    jwt = (
        "eyJ" + "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "doNotLeakThisSignature123"
    )
    encoded_github_token = base64.b64encode(github_token.encode()).decode()

    return [
        DetectionCase(
            "AWS access key ID",
            f'aws_key = "{aws_access_key}"',
            True,
            "AWS Access Key ID",
        ),
        DetectionCase(
            "AWS temporary access key ID",
            f'"access_key_id": "{aws_temporary_key}"',
            True,
            "AWS Access Key ID",
        ),
        DetectionCase(
            "AWS secret access key",
            f'aws_secret_access_key = "{aws_secret_key}"',
            True,
            "AWS Secret Access Key",
        ),
        DetectionCase(
            "Malformed AWS secret access key",
            f'aws_secret_access_key = "{aws_secret_key}x"',
            False,
        ),
        DetectionCase(
            "Google API key in JSON",
            f'"api_key": "{google_key}"',
            True,
            "Google API Key",
        ),
        DetectionCase(
            "Google API key in environment file",
            f"GOOGLE_API_KEY={google_key}",
            True,
            "Google API Key",
        ),
        DetectionCase(
            "Stripe test secret key",
            f"STRIPE_SECRET_KEY={stripe_test_key}",
            True,
            "Stripe API Key",
        ),
        DetectionCase(
            "Stripe live secret key",
            f'stripe_key = "{stripe_live_key}"',
            True,
            "Stripe API Key",
        ),
        DetectionCase(
            "Stripe restricted key",
            f"stripe_key: {stripe_restricted_key}",
            True,
            "Stripe API Key",
        ),
        DetectionCase(
            "GitHub token",
            f'token = "{github_token}"',
            True,
            "GitHub Token",
        ),
        DetectionCase(
            "Base64-encoded GitHub token in a secret field",
            f'token = "{encoded_github_token}"',
            True,
            "GitHub Token",
        ),
        DetectionCase(
            "Slack bot token",
            f"SLACK_BOT_TOKEN={slack_token}",
            True,
            "Slack Token",
        ),
        DetectionCase(
            "Slack user token",
            f"SLACK_USER_TOKEN={slack_user_token}",
            True,
            "Slack Token",
        ),
        DetectionCase(
            "Twilio API key",
            f'twilio_key = "{twilio_key}"',
            True,
            "Twilio Secret Key",
        ),
        DetectionCase(
            "Private key header",
            "-----BEGIN RSA PRIVATE KEY-----",
            True,
            "Private Key",
        ),
        DetectionCase(
            "Complete private key block",
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "synthetic-private-key-material\n"
            "-----END RSA PRIVATE KEY-----",
            True,
            "Private Key",
        ),
        DetectionCase(
            "Complete OpenSSH private key block",
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "synthetic-openssh-key-material\n"
            "-----END OPENSSH PRIVATE KEY-----",
            True,
            "Private Key",
        ),
        DetectionCase(
            "Database connection URI",
            f'database = "{database_uri}"',
            True,
            "Database Connection URI",
        ),
        DetectionCase(
            "MySQL connection URI",
            f'database_url = "{mysql_uri}"',
            True,
            "Database Connection URI",
        ),
        DetectionCase(
            "Redis connection URI with encoded password punctuation",
            f'cache_url = "{redis_uri}"',
            True,
            "Database Connection URI",
        ),
        DetectionCase(
            "Generic token assignment",
            f'token = "{generic_token}"',
            True,
            "Generic Secret Assignment",
        ),
        DetectionCase(
            "Generic password in YAML",
            f"password: {generic_token}",
            True,
            "Generic Secret Assignment",
        ),
        DetectionCase(
            "OpenAI project key",
            f'openai_key = "{openai_key}"',
            True,
            "OpenAI API Key",
        ),
        DetectionCase(
            "Anthropic key",
            f'api_key = "{anthropic_key}"',
            True,
            "Anthropic API Key",
        ),
        DetectionCase(
            "Hugging Face token",
            f"HF_TOKEN={huggingface_token}",
            True,
            "HuggingFace Token",
        ),
        DetectionCase(
            "PyPI upload token",
            f'pypi_token = "{pypi_token}"',
            True,
            "PyPI API Token",
        ),
        DetectionCase(
            "npm access token",
            f"NPM_TOKEN={npm_token}",
            True,
            "NPM Access Token",
        ),
        DetectionCase(
            "dotenv prefixed API key",
            f"PAYMENTS_API_KEY={generic_token}",
            True,
            "Generic Secret Assignment",
        ),
        DetectionCase(
            "YAML service token",
            f'service_token: "{service_secret}"',
            True,
            "Generic Secret Assignment",
        ),
        DetectionCase(
            "JSON client secret",
            f'{{"client_secret": "{service_secret}"}}',
            True,
            "Generic Secret Assignment",
        ),
        DetectionCase(
            "TOML OAuth token",
            f'oauth_token = "{access_token}"',
            True,
            "Generic Secret Assignment",
        ),
        DetectionCase(
            "Python camel-case client secret",
            f'clientSecret = "{service_secret}"',
            True,
            "Generic Secret Assignment",
        ),
        DetectionCase(
            "JavaScript camel-case access token",
            f'const accessToken = "{access_token}";',
            True,
            "Generic Secret Assignment",
        ),
        DetectionCase(
            "Shell exported token",
            f"export DEPLOYMENT_TOKEN={access_token}",
            True,
            "Generic Secret Assignment",
        ),
        DetectionCase(
            "Laravel base64 application key",
            f"APP_KEY=base64:{legacy_secret}",
            True,
            "Generic Secret Assignment",
        ),
        DetectionCase(
            "Rails secret key base",
            f'secret_key_base = "{legacy_secret}"',
            True,
            "Generic Secret Assignment",
        ),
        DetectionCase(
            "Rails master key",
            f'master_key = "{legacy_secret}"',
            True,
            "Generic Secret Assignment",
        ),
        DetectionCase(
            "Legacy password field",
            f'pass = "{legacy_secret}"',
            True,
            "Generic Secret Assignment",
        ),
        DetectionCase(
            "XML password attribute",
            f'<server password="{legacy_secret}" />',
            True,
            "Generic Secret Assignment",
        ),
        DetectionCase(
            "Netrc password entry",
            f"machine example.test login deploy password {legacy_secret}",
            True,
            "Netrc Password",
            ".netrc",
        ),
        DetectionCase(
            "PostgreSQL password file entry",
            f"db.example.test:5432:service:deploy:{legacy_secret}",
            True,
            "PostgreSQL Password File",
            ".pgpass",
        ),
        DetectionCase(
            "Docker registry auth",
            '{"auths":{"registry.example.test":{"auth":"dXNlcjpwYXNz"}}}',
            True,
            "Docker Registry Auth",
            ".docker/config.json",
        ),
        DetectionCase(
            "High-entropy secret field",
            f'secret = "{high_entropy_value}"',
            True,
            "High entropy string",
        ),
        DetectionCase("JWT", f'jwt = "{jwt}"', True, "JWT"),
        DetectionCase(
            "Password keyword argument",
            "        password=password,",
            False,
            source="client.py",
        ),
        DetectionCase(
            "Password attribute keyword argument",
            "        key_password=self.key_password,",
            False,
            source="connection.py",
        ),
        DetectionCase(
            "Password from function call",
            "url, netloc, url_user_password = split_auth_netloc_from_url(",
            False,
            source="auth.py",
        ),
        DetectionCase(
            "Password unpacked from variable",
            "username, password = index_url_user_password",
            False,
            source="auth.py",
        ),
        DetectionCase(
            "Generic key from function call",
            "api_key = load_api_key_from_environment()",
            False,
            source="settings.py",
        ),
        DetectionCase(
            "Unquoted password in source code",
            "PASSWORD=Summer2024!",
            False,
            source="settings.py",
        ),
        DetectionCase(
            "Unquoted password in shell config",
            "export DB_PASSWORD=Summer2024!",
            True,
            "Password Assignment",
            "deploy.sh",
        ),
        DetectionCase(
            "Unrelated entropy beside secret terminology",
            f'print("secret rotation complete", "{unrelated_entropy}")',
            False,
        ),
        DetectionCase(
            "Stripe publishable key",
            f'publishable_key = "{stripe_publishable_key}"',
            False,
        ),
        DetectionCase(
            "Short AWS access key lookalike",
            'aws_key = "AKIA1234567890"',
            False,
        ),
        DetectionCase(
            "Short Slack token lookalike",
            'slack_token = "xoxb-short"',
            False,
        ),
        DetectionCase(
            "Anthropic token prefix in documentation",
            'example = "sk-ant-placeholder"',
            False,
        ),
        DetectionCase(
            "Truncated GitHub token in a secret field",
            'token = "ghp_1234567890"',
            False,
        ),
        DetectionCase(
            "Truncated Google API key in a secret field",
            'api_key = "AIza1234"',
            False,
        ),
        DetectionCase(
            "Malformed JWT with only two segments",
            'jwt = "eyJheader.eyJpayload"',
            False,
        ),
        DetectionCase(
            "SSH public key",
            f'public_key = "{ssh_public_key}"',
            False,
        ),
        DetectionCase(
            "Docker auth without a password",
            '{"auths":{"registry.example.test":{"auth":"dXNlcg=="}}}',
            False,
            source=".docker/config.json",
        ),
        DetectionCase(
            "High-entropy key identifier",
            f'key_id = "{unrelated_entropy}"',
            False,
        ),
        DetectionCase(
            "Credential setup documentation",
            'description = "Set API_KEY through deployment settings."',
            False,
        ),
        DetectionCase(
            "Password policy text",
            'password_policy = "Require mixed case and punctuation."',
            False,
        ),
        DetectionCase(
            "Ordinary cache key",
            f'cache_key = "{unrelated_entropy}"',
            False,
        ),
        DetectionCase(
            "Checksum field",
            f'checksum = "{unrelated_entropy}"',
            False,
        ),
        DetectionCase(
            "Encoded checksum",
            f'checksum = "{encoded_github_token}"',
            False,
        ),
        DetectionCase(
            "Release version identifier",
            'release = "2026.11.05-build.42"',
            False,
        ),
        DetectionCase(
            "Credential field placeholder",
            'api_key = "replace-me"',
            False,
        ),
        DetectionCase(
            "API key template",
            'api_key = "YOUR_API_KEY_HERE"',
            False,
        ),
        DetectionCase(
            "Vault token template",
            'token = "replace-with-token-from-vault"',
            False,
        ),
        DetectionCase(
            "Password setup placeholder",
            'password = "change-this-before-deploy"',
            False,
        ),
        DetectionCase(
            "Environment variable name without a value",
            'required_setting = "GEMINI_API_KEY"',
            False,
        ),
        DetectionCase(
            "Empty secret setting",
            'api_key = ""',
            False,
        ),
        DetectionCase(
            "Unset token setting",
            "token = None",
            False,
        ),
        DetectionCase(
            "Public key declaration",
            'public_key = "-----BEGIN PUBLIC KEY-----"',
            False,
        ),
        DetectionCase(
            "Documented settings",
            'message = "Set API keys in deployment settings."',
            False,
        ),
        DetectionCase(
            "Example account credentials",
            '{"username": "demo", "password": "password"}',
            False,
        ),
        DetectionCase(
            "Database URI with environment placeholder",
            "database_url = "
            '"postgresql://app:${DB_PASSWORD}@db.example.com/app"',
            False,
        ),
        DetectionCase(
            "Database URI with shell variable",
            'database_url = "mysql://app:$DB_PASSWORD@db.example.com/app"',
            False,
        ),
        DetectionCase(
            "Database URI with template placeholder",
            'database_url = "redis://app:{{ redis_password }}@cache.example.com/0"',
            False,
        ),
        DetectionCase(
            "Public client configuration",
            'const publicKey = "use-the-public-client-identifier";',
            False,
        ),
        DetectionCase(
            "Secret environment variable reference",
            'service_token = "${DEPLOYMENT_TOKEN}"',
            False,
        ),
        DetectionCase(
            "Terraform variable description",
            'description = "Supply the database password at deploy time."',
            False,
        ),
        DetectionCase(
            "Public key setting",
            f'public_key = "{legacy_secret}"',
            False,
        ),
        DetectionCase(
            "Client identifier",
            f'client_id = "{legacy_secret}"',
            False,
        ),
        DetectionCase(
            "Application key environment reference",
            'APP_KEY="${APP_KEY}"',
            False,
        ),
        DetectionCase(
            "Netrc environment reference",
            "machine example.test login deploy password ${DEPLOY_PASSWORD}",
            False,
            source=".netrc",
        ),
        DetectionCase(
            "PostgreSQL wildcard password",
            "db.example.test:5432:service:deploy:*",
            False,
            source=".pgpass",
        ),
        DetectionCase(
            "Malformed Docker auth value",
            '{"auths":{"registry.example.test":{"auth":"not-base64!"}}}',
            False,
            source=".docker/config.json",
        ),
    ]


def evaluate_cases(
    cases: list[DetectionCase],
) -> tuple[DetectionMetrics, dict[str, DetectionMetrics]]:
    """Return finding-level metrics overall and for each reported detector."""
    overall_counts: Counter[str] = Counter()
    detector_counts: dict[str, Counter[str]] = {}
    for case in cases:
        expected = Counter(
            {case.expected_matcher: 1}
            if case.should_detect and case.expected_matcher
            else {}
        )
        actual = Counter(
            issue["matcher"]
            for issue in scan_text(case.content, case.source or case.name)
        )
        for matcher in expected.keys() | actual.keys():
            counts = detector_counts.setdefault(matcher, Counter())
            true_positive = min(expected[matcher], actual[matcher])
            false_positive = actual[matcher] - true_positive
            false_negative = expected[matcher] - true_positive
            for key, value in (
                ("true_positive", true_positive),
                ("false_positive", false_positive),
                ("false_negative", false_negative),
            ):
                counts[key] += value
                overall_counts[key] += value

    overall = DetectionMetrics(
        true_positive=overall_counts["true_positive"],
        false_positive=overall_counts["false_positive"],
        false_negative=overall_counts["false_negative"],
    )
    per_detector = {
        matcher: DetectionMetrics(
            true_positive=counts["true_positive"],
            false_positive=counts["false_positive"],
            false_negative=counts["false_negative"],
        )
        for matcher, counts in sorted(detector_counts.items())
    }
    return overall, per_detector


class TestDetectionQuality(unittest.TestCase):
    """Check that the scanner performs consistently on labeled synthetic cases."""

    def test_specific_matches_are_not_reported_as_generic_assignments(self) -> None:
        """A specific format match should not be duplicated by the generic rule."""
        cases = build_cases()
        overlapping_cases = [
            case
            for case in cases
            if case.expected_matcher
            in {
                "Google API Key",
                "Stripe API Key",
                "GitHub Token",
                "Slack Token",
                "HuggingFace Token",
                "PyPI API Token",
                "NPM Access Token",
            }
        ]

        for case in overlapping_cases:
            with self.subTest(case=case.name):
                matches = scan_text(case.content, case.source or case.name)
                self.assertEqual(
                    [issue["matcher"] for issue in matches],
                    [case.expected_matcher],
                )

    def test_anthropic_key_is_not_misclassified_as_openai(self) -> None:
        """Anthropic's shared key prefix must not trigger the OpenAI rule."""
        case = next(
            case
            for case in build_cases()
            if case.expected_matcher == "Anthropic API Key"
        )

        matches = scan_text(case.content, case.source or case.name)

        self.assertEqual(
            [issue["matcher"] for issue in matches],
            ["Anthropic API Key"],
        )

    def test_metrics_are_finding_level_and_report_each_detector(self) -> None:
        """Per-detector totals must account for every expected and actual match."""
        cases = build_cases()
        overall, per_detector = evaluate_cases(cases)

        self.assertEqual(
            overall.true_positive,
            sum(case.should_detect for case in cases),
        )
        self.assertEqual(overall.false_positive, 0)
        self.assertEqual(overall.false_negative, 0)
        self.assertEqual(
            sum(metrics.true_positive for metrics in per_detector.values()),
            overall.true_positive,
        )
        self.assertTrue(
            all(
                metrics.precision == 1.0 and metrics.recall == 1.0
                for metrics in per_detector.values()
            )
        )

    def test_metrics_count_wrong_detector_as_false_positive_and_negative(self) -> None:
        """A finding with the wrong detector must not count as a correct case."""
        case = DetectionCase(
            name="misclassified Anthropic key",
            content=(
                'api_key = "sk-ant-'
                '0123456789abcdefghijklmnopqrstuvwxyz"'
            ),
            should_detect=True,
            expected_matcher="OpenAI API Key",
        )

        overall, per_detector = evaluate_cases([case])

        self.assertEqual(overall.true_positive, 0)
        self.assertEqual(overall.false_positive, 1)
        self.assertEqual(overall.false_negative, 1)
        self.assertEqual(
            per_detector["Anthropic API Key"].false_positive,
            1,
        )
        self.assertEqual(
            per_detector["OpenAI API Key"].false_negative,
            1,
        )
        self.assertEqual(overall.precision, 0.0)
        self.assertEqual(overall.recall, 0.0)

    def test_synthetic_corpus_precision_and_recall(self) -> None:
        """Report corpus precision and recall and guard its current examples."""
        cases = build_cases()
        metrics, per_detector = evaluate_cases(cases)
        precision = metrics.precision or 0.0
        recall = metrics.recall or 0.0

        print(
            f"Synthetic corpus v{CORPUS_VERSION} (rule pack {RULE_PACK_VERSION}): "
            f"TP={metrics.true_positive}, FP={metrics.false_positive}, "
            f"FN={metrics.false_negative}, precision={precision:.0%}, "
            f"recall={recall:.0%}"
        )
        for matcher, detector_metrics in per_detector.items():
            detector_precision = (
                f"{detector_metrics.precision:.0%}"
                if detector_metrics.precision is not None
                else "n/a"
            )
            detector_recall = (
                f"{detector_metrics.recall:.0%}"
                if detector_metrics.recall is not None
                else "n/a"
            )
            print(
                f"  {matcher}: TP={detector_metrics.true_positive}, "
                f"FP={detector_metrics.false_positive}, "
                f"FN={detector_metrics.false_negative}, "
                f"precision={detector_precision}, recall={detector_recall}"
            )
        unlabeled_cases = [
            case.name
            for case in cases
            if case.should_detect and not case.expected_matcher
        ]
        missing_matchers = [
            case.name
            for case in cases
            if case.expected_matcher
            and case.expected_matcher
            not in {
                issue["matcher"]
                for issue in scan_text(case.content, case.source or case.name)
            }
        ]
        critical_matchers = {
            "Docker Registry Auth",
            "Netrc Password",
            "PostgreSQL Password File",
        }
        incorrect_severity = [
            case.name
            for case in cases
            if case.expected_matcher in critical_matchers
            and any(
                issue["matcher"] == case.expected_matcher
                and issue["severity"] != "CRITICAL"
                for issue in scan_text(case.content, case.source or case.name)
            )
        ]
        matcher_mismatches = [
            f"{case.name}: expected "
            f"{case.expected_matcher if case.should_detect else 'no finding'}, got "
            f"{', '.join(issue['matcher'] for issue in scan_text(case.content, case.source or case.name)) or 'no finding'}"
            for case in cases
            if Counter(
                issue["matcher"]
                for issue in scan_text(case.content, case.source or case.name)
            )
            != Counter(
                {case.expected_matcher: 1}
                if case.should_detect and case.expected_matcher
                else {}
            )
        ]
        false_negative_cases = [
            case.name
            for case in cases
            if case.should_detect
            and not scan_text(case.content, case.source or case.name)
        ]
        self.assertEqual(unlabeled_cases, [])
        self.assertEqual(missing_matchers, [])
        self.assertEqual(incorrect_severity, [])
        self.assertEqual(metrics.false_positive, 0, matcher_mismatches)
        self.assertEqual(metrics.false_negative, 0, false_negative_cases)
        self.assertGreaterEqual(precision, 0.95)
        self.assertGreaterEqual(recall, 0.95)


if __name__ == "__main__":
    unittest.main()
