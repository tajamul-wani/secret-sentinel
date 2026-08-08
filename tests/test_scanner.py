import unittest

from secret_sentinel.scanner import scan_text


class TestScanner(unittest.TestCase):
    def test_scan_text_detects_aws_key(self):
        content = "api_key = \"AKIAAAAAAAAAAAAAAAAA\"\n"
        issues = scan_text(content, "test.py")
        self.assertTrue(any(issue["matcher"] == "AWS Secret Access Key" for issue in issues))

    def test_scan_text_detects_entropy_string(self):
        content = "secret = \"QwertyUIOPasdfghJKLzxcvb1234\"\n"
        issues = scan_text(content, "test.py")
        self.assertTrue(any(issue["matcher"] == "High entropy string" for issue in issues))


if __name__ == "__main__":
    unittest.main()
