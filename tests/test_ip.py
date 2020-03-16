"""
    Tests of ip.py
"""

import unittest

from src.ip import IP


class TestIP(unittest.TestCase):
    """Tests of IP class"""
    private_ipv4 = [
        "10.0.0.0", "10.1.2.3", "10.255.255.255",
        "172.16.0.0", "172.20.1.3", "172.31.255.255",
        "192.168.0.0", "192.168.45.2", "192.168.255.255",
        "0.0.0.0", "127.0.0.1"
    ]

    public_ipv4 = [
        "1.1.1.1", "8.8.8.8", "150.0.1.6"
    ]

    private_ipv6 = [
        "fd00::", "fd12:3456:789a:1::1", "fe80::"
    ]

    public_ipv6 = [
        "7894:2222:2222:3333:4444:4444:4444:4444"
    ]

    non_ip = [
        "hello", "123456", "+"
    ]

    def test_is_ipv4(self) -> None:
        """is_ipv4"""
        for addr in self.private_ipv4:
            self.assertTrue(IP.is_ipv4(addr))

        for addr in self.public_ipv4:
            self.assertTrue(IP.is_ipv4(addr))

        for addr in self.private_ipv6:
            self.assertFalse(IP.is_ipv4(addr))

        for addr in self.public_ipv6:
            self.assertFalse(IP.is_ipv4(addr))

    def test_is_ipv6(self) -> None:
        """is_ipv6"""
        for addr in self.private_ipv4:
            self.assertFalse(IP.is_ipv6(addr))

        for addr in self.public_ipv4:
            self.assertFalse(IP.is_ipv6(addr))

        for addr in self.private_ipv6:
            self.assertTrue(IP.is_ipv6(addr))

        for addr in self.public_ipv6:
            self.assertTrue(IP.is_ipv6(addr))

    def test_is_ip(self) -> None:
        """is_ip"""
        for addr in self.private_ipv4:
            self.assertTrue(IP.is_ip(addr))

        for addr in self.public_ipv4:
            self.assertTrue(IP.is_ip(addr))

        for addr in self.private_ipv6:
            self.assertTrue(IP.is_ip(addr))

        for addr in self.public_ipv6:
            self.assertTrue(IP.is_ip(addr))

        for addr in self.non_ip:
            self.assertFalse(IP.is_ip(addr))

    def test_is_private(self) -> None:
        """is_private"""
        for addr in self.private_ipv4:
            self.assertTrue(IP.is_private(addr))

        for addr in self.public_ipv4:
            self.assertFalse(IP.is_private(addr))

        for addr in self.private_ipv6:
            self.assertTrue(IP.is_private(addr))

        for addr in self.public_ipv6:
            self.assertFalse(IP.is_private(addr))
