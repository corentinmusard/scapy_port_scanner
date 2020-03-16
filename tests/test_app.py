"""
    Tests of app.py
"""

import unittest

from src.app import is_tool


class TestTcp(unittest.TestCase):
    """Tests of app.py"""

    def test_is_tool(self) -> None:
        """is_tool"""
        self.assertTrue(is_tool("python"))
        self.assertFalse(is_tool("DoNotExist"))
