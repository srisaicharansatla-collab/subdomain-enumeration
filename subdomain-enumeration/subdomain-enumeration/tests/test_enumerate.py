import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import enumerate as subenum


class SubdomainTests(unittest.TestCase):
    def test_domain_validation(self):
        self.assertTrue(subenum.valid_domain("example.com"))
        self.assertFalse(subenum.valid_domain("192.0.2.1"))
        self.assertFalse(subenum.valid_domain("-bad.example.com"))

    @patch("enumerate.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("192.0.2.2", 0))])
    def test_resolves_candidate(self, resolver):
        self.assertEqual(subenum.resolve("example.com", "www"), ("www.example.com", ["192.0.2.2"]))


if __name__ == "__main__":
    unittest.main()
