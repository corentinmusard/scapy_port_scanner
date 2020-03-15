"""
    Tests of tcp.py
"""

import unittest

from src.tcp import TCP


class TestTcp(unittest.TestCase):
    """Tests of TCP class"""

    def test_scanflags(self):
        """scanflags"""
        self.assertEqual(TCP.scanflags(""), "")
        self.assertEqual(TCP.scanflags("FIN"), "F")
        self.assertEqual(TCP.scanflags("ACK"), "A")
        self.assertEqual(TCP.scanflags("WRG"), "")
        self.assertEqual(TCP.scanflags("FINFIN"), "F")
        self.assertEqual(TCP.scanflags("FINECE"), "FE")
