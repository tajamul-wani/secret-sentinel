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


if __name__ == "__main__":
    unittest.main()
