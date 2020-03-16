"""
    IP layer
"""

import ipaddress


class IP:
    """Basics checks of an ip adress."""
    @classmethod
    def is_ip(cls, ip: str) -> bool:
        """Check if the string argument is an IP (IPv4 or IPV6)."""
        return cls.is_ipv4(ip) or cls.is_ipv6(ip)

    @staticmethod
    def is_ipv4(ip: str) -> bool:
        """Check if the string argument is an IPv4."""
        try:
            ipaddress.IPv4Address(ip)
        except ipaddress.AddressValueError:
            return False

        return True

    @staticmethod
    def is_ipv6(ip: str) -> bool:
        """Check if the string argument is an IPv6."""
        try:
            ipaddress.IPv6Address(ip)
        except ipaddress.AddressValueError:
            return False

        return True

    @staticmethod
    def is_private(ip: str) -> bool:
        """Check if the string argument is a private IP.
           Work for IPv4 and IPv6.
        """
        return ipaddress.ip_address(ip).is_private
