"""Labeled synthetic cases for scanner precision and recall regressions."""

import sys
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from secret_sentinel.scanner import scan_text


@dataclass(frozen=True)
class DetectionCase:
    """One labeled input for the scanner's small regression corpus."""

    name: str
    content: str
    should_detect: bool


def build_cases() -> List[DetectionCase]:
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
    twilio_key = "SK" + "1234567890abcdef" * 2
    database_password = "password" + "Example123"
    database_uri = "postgresql://app:" + database_password + "@db.example.com/app"
    generic_token = "token_" + "0123456789abcdef01234567"
    openai_key = "sk-proj-" + "0123456789abcdefghijklmnopqrstuvwxyz"
    anthropic_key = "sk-ant-" + "0123456789abcdefghijklmnopqrstuvwxyz"
    huggingface_token = "hf_" + "1234567890abcdefghijklmnopqrstuvwx"
    pypi_token = (
        "pypi-AgEIcHlwaS5vcmc"
        + "1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdef"
    )
    npm_token = "npm_" + "1234567890abcdefghijklmnopqrstuvwxyz"
    high_entropy_value = "K9zXwQ7p.L2vM5yB8.tR4cE1aD3.fG6hJ0n"
    unrelated_entropy = "P8mQ2rV6xN4bK9sT1wC7dF3hJ5aL0eG"
    jwt = (
        "eyJ" + "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "doNotLeakThisSignature123"
    )

    return [
        DetectionCase("AWS access key ID", f'aws_key = "{aws_access_key}"', True),
        DetectionCase(
            "AWS temporary access key ID",
            f'"access_key_id": "{aws_temporary_key}"',
            True,
        ),
        DetectionCase(
            "AWS secret access key",
            f'aws_secret_access_key = "{aws_secret_key}"',
            True,
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
        ),
        DetectionCase(
            "Google API key in environment file",
            f"GOOGLE_API_KEY={google_key}",
            True,
        ),
        DetectionCase(
            "Stripe test secret key",
            f"STRIPE_SECRET_KEY={stripe_test_key}",
            True,
        ),
        DetectionCase(
            "Stripe live secret key",
            f'stripe_key = "{stripe_live_key}"',
            True,
        ),
        DetectionCase(
            "Stripe restricted key",
            f"stripe_key: {stripe_restricted_key}",
            True,
        ),
        DetectionCase("GitHub token", f'token = "{github_token}"', True),
        DetectionCase("Slack bot token", f"SLACK_BOT_TOKEN={slack_token}", True),
        DetectionCase("Twilio API key", f'twilio_key = "{twilio_key}"', True),
        DetectionCase(
            "Private key header",
            "-----BEGIN RSA PRIVATE KEY-----",
            True,
        ),
        DetectionCase("Database connection URI", f'database = "{database_uri}"', True),
        DetectionCase("Generic token assignment", f'token = "{generic_token}"', True),
        DetectionCase("Generic password in YAML", f"password: {generic_token}", True),
        DetectionCase("OpenAI project key", f'openai_key = "{openai_key}"', True),
        DetectionCase("Anthropic key", f'api_key = "{anthropic_key}"', True),
        DetectionCase("Hugging Face token", f"HF_TOKEN={huggingface_token}", True),
        DetectionCase("PyPI upload token", f'pypi_token = "{pypi_token}"', True),
        DetectionCase("npm access token", f"NPM_TOKEN={npm_token}", True),
        DetectionCase(
            "High-entropy secret field",
            f'secret = "{high_entropy_value}"',
            True,
        ),
        DetectionCase("JWT", f'jwt = "{jwt}"', True),
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
    ]


def evaluate_cases(cases: List[DetectionCase]) -> Tuple[int, int, int, int]:
    """Return true-positive, false-positive, true-negative, and false-negative."""
    true_positive = false_positive = true_negative = false_negative = 0
    for case in cases:
        detected = bool(scan_text(case.content, case.name))
        if detected and case.should_detect:
            true_positive += 1
        elif detected:
            false_positive += 1
        elif case.should_detect:
            false_negative += 1
        else:
            true_negative += 1
    return true_positive, false_positive, true_negative, false_negative


class TestDetectionQuality(unittest.TestCase):
    """Check that the scanner performs consistently on labeled synthetic cases."""

    def test_synthetic_corpus_precision_and_recall(self) -> None:
        """Report corpus precision and recall and guard its current examples."""
        cases = build_cases()
        (
            true_positive,
            false_positive,
            true_negative,
            false_negative,
        ) = evaluate_cases(cases)
        precision = true_positive / (true_positive + false_positive)
        recall = true_positive / (true_positive + false_negative)

        print(
            "Synthetic corpus: "
            f"TP={true_positive}, FP={false_positive}, TN={true_negative}, "
            f"FN={false_negative}, precision={precision:.0%}, recall={recall:.0%}"
        )
        false_positive_cases = [
            case.name
            for case in cases
            if not case.should_detect and scan_text(case.content, case.name)
        ]
        false_negative_cases = [
            case.name
            for case in cases
            if case.should_detect and not scan_text(case.content, case.name)
        ]
        self.assertEqual(false_positive, 0, false_positive_cases)
        self.assertEqual(false_negative, 0, false_negative_cases)


if __name__ == "__main__":
    unittest.main()
