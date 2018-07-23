"""
    A module docstring.
"""

import unittest

from src import app


class TestBot(unittest.TestCase):
    """docstring for TestBot"""

    def test_something(self):
        """Random test for test tests."""
        self.assertEqual(app.TCP.FIN, 0x1)
