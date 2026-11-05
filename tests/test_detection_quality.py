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
    """Build representative positive and negative inputs without real credentials."""
    aws_access_key = "AKIA" + "1234567890ABCDEF"
    aws_secret_key = "AbCd1234" * 5
    google_key = "AIza" + "AbCdEfGhIjKlMnOpQrStUvWxYz012345678"
    stripe_secret_key = "sk_live_" + "123456789012345678901234"
    stripe_publishable_key = "pk_live_" + "123456789012345678901234"
    github_token = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz"
    database_password = "password" + "Example123"
    database_uri = "postgresql://app:" + database_password + "@db.example.com/app"
    generic_token = "token_" + "0123456789abcdef01234567"
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
            "AWS secret access key",
            f'aws_secret_access_key = "{aws_secret_key}"',
            True,
        ),
        DetectionCase(
            "Malformed AWS secret access key",
            f'aws_secret_access_key = "{aws_secret_key}x"',
            False,
        ),
        DetectionCase("Google API key", f'"api_key": "{google_key}"', True),
        DetectionCase("Stripe secret key", f'stripe_key = "{stripe_secret_key}"', True),
        DetectionCase("GitHub token", f'token = "{github_token}"', True),
        DetectionCase("Database connection URI", f'database = "{database_uri}"', True),
        DetectionCase("Generic token assignment", f'token = "{generic_token}"', True),
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
