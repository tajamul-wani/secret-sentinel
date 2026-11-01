"""Tests for configuration loader."""

import configparser
import tempfile
import unittest
from pathlib import Path

from secret_sentinel.config import SecretSentinelConfig
from secret_sentinel.risk_scoring import SeverityLevel


class TestConfig(unittest.TestCase):
    """Test suite for SecretSentinelConfig."""

    def test_load_default(self) -> None:
        """Default configuration should keep AI disabled and use LOW fail threshold."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = SecretSentinelConfig.load(tmpdir)
            self.assertFalse(config.ai_enabled)
            self.assertFalse(config.ai_cloud_enabled)
            self.assertIn(".git/*", config.ignore_globs)
            self.assertEqual(config.fail_on, SeverityLevel.LOW)

    def test_load_custom_config(self) -> None:
        """Custom configuration from ini should override defaults."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / ".secret-sentinel.ini"
            parser = configparser.ConfigParser()
            parser["secret-sentinel"] = {
                "ignore_paths": "tests/*, docs/*",
                "ai_enabled": "true",
                "ai_cloud_enabled": "true",
                "fail_on": "HIGH",
            }
            with config_path.open("w", encoding="utf-8") as handle:
                parser.write(handle)
            config = SecretSentinelConfig.load(tmpdir)
            self.assertTrue(config.ai_enabled)
            self.assertTrue(config.ai_cloud_enabled)
            self.assertIn("tests/*", config.ignore_globs)
            self.assertIn("docs/*", config.ignore_globs)
            self.assertEqual(config.fail_on, SeverityLevel.HIGH)

    def test_load_with_secretignore(self) -> None:
        """Patterns in .secretignore should be added to ignore_globs."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ignore_path = Path(tmpdir) / ".secretignore"
            with ignore_path.open("w", encoding="utf-8") as handle:
                handle.write("# Comment line\n\nfixtures/*\nmock_data/*.json\n")

            config = SecretSentinelConfig.load(tmpdir)
            self.assertIn("fixtures/*", config.ignore_globs)
            self.assertIn("mock_data/*.json", config.ignore_globs)

    def test_load_invalid_fail_on(self) -> None:
        """Invalid fail_on value should fall back to LOW."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / ".secret-sentinel.ini"
            parser = configparser.ConfigParser()
            parser["secret-sentinel"] = {
                "fail_on": "INVALID_LEVEL",
            }
            with config_path.open("w", encoding="utf-8") as handle:
                parser.write(handle)
            config = SecretSentinelConfig.load(tmpdir)
            self.assertEqual(config.fail_on, SeverityLevel.LOW)

    def test_load_custom_rules(self) -> None:
        """Custom rules preserve names, regex syntax, and configured severity."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / ".secret-sentinel.ini"
            config_path.write_text(
                "[custom_rules]\n"
                "Internal API Token = CRITICAL | \\bcorp_[A-Za-z0-9]{32}\\b\n"
                "Build Password = HIGH | password=[^\\s]+\n",
                encoding="utf-8",
            )

            config = SecretSentinelConfig.load(tmpdir)

        self.assertEqual(
            [rule.name for rule in config.custom_rules],
            ["Internal API Token", "Build Password"],
        )
        self.assertEqual(config.custom_rules[0].severity, SeverityLevel.CRITICAL)
        self.assertIsNotNone(config.custom_rules[0].pattern.search("corp_" + "a" * 32))
        self.assertEqual(config.custom_rules[1].severity, SeverityLevel.HIGH)

    def test_load_rejects_malformed_custom_rule(self) -> None:
        """Invalid custom-rule definitions fail with a useful configuration error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / ".secret-sentinel.ini"
            config_path.write_text(
                "[custom_rules]\n"
                "Broken Rule = CRITICAL | [invalid\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "invalid regular expression"):
                SecretSentinelConfig.load(tmpdir)

    def test_load_rejects_invalid_custom_rule_severity(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / ".secret-sentinel.ini"
            config_path.write_text(
                "[custom_rules]\n"
                "Internal Token = URGENT | token_[A-Za-z0-9]+\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "invalid severity"):
                SecretSentinelConfig.load(tmpdir)

    def test_load_rejects_empty_matching_custom_rule(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / ".secret-sentinel.ini"
            config_path.write_text(
                "[custom_rules]\n"
                "Empty Match = HIGH | a*\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "must not match an empty string"):
                SecretSentinelConfig.load(tmpdir)


if __name__ == "__main__":
    unittest.main()
