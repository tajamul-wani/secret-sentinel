import configparser
import tempfile
import unittest
from pathlib import Path

from secret_sentinel.config import SecretSentinelConfig


class TestConfig(unittest.TestCase):
    def test_load_default(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config = SecretSentinelConfig.load(tmpdir)
            self.assertTrue(config.ai_enabled)
            self.assertIn(".git/*", config.ignore_globs)

    def test_load_custom_config(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / ".secret-sentinel.ini"
            parser = configparser.ConfigParser()
            parser["secret-sentinel"] = {
                "ignore_paths": "tests/*, docs/*",
                "ai_enabled": "false",
            }
            with config_path.open("w", encoding="utf-8") as handle:
                parser.write(handle)
            config = SecretSentinelConfig.load(tmpdir)
            self.assertFalse(config.ai_enabled)
            self.assertIn("tests/*", config.ignore_globs)
            self.assertIn("docs/*", config.ignore_globs)


if __name__ == "__main__":
    unittest.main()
