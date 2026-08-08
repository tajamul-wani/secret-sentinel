import unittest

from secret_sentinel.utils import shannon_entropy


class TestUtils(unittest.TestCase):
    def test_shannon_entropy_empty(self):
        self.assertEqual(shannon_entropy(""), 0.0)

    def test_shannon_entropy_low(self):
        self.assertAlmostEqual(shannon_entropy("aaaaaa"), 0.0, places=3)

    def test_shannon_entropy_high(self):
        self.assertGreater(shannon_entropy("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"), 4.0)


if __name__ == "__main__":
    unittest.main()
