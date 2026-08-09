import unittest

from secret_sentinel.cli import parse_args_from


class TestCLI(unittest.TestCase):
    def test_parse_args_for_staged_scan(self):
        args = parse_args_from(["--staged"])
        self.assertTrue(args.staged)
        self.assertFalse(args.no_ai)

    def test_parse_args_for_file_paths(self):
        args = parse_args_from(["src", "tests"])
        self.assertEqual(args.paths, ["src", "tests"])
        self.assertFalse(args.staged)

    def test_parse_args_hook_install(self):
        args = parse_args_from(["--install-hook"])
        self.assertTrue(args.install_hook)
        self.assertFalse(args.uninstall_hook)

    def test_parse_args_debug_mode(self):
        args = parse_args_from(["--debug", "--staged"])
        self.assertTrue(args.debug)
        self.assertTrue(args.staged)


if __name__ == "__main__":
    unittest.main()
