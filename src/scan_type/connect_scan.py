"""
    A module docstring.
"""

from typing import List
import socket
import argparse

from .. import app, log
from ..scan import Scan


class ConnectScan(Scan):
    """docstring for ConnectScan"""
    def __init__(self, args: argparse.Namespace = None) -> None:
        super(ConnectScan, self).__init__(args)

        self.port_list = app.most_used_ports('tcp', self.args.top_ports)

        if self.ipv6:
            self.family = socket.AF_INET6
        else:
            self.family = socket.AF_INET

        self.results['opened'] = 0
        self.results['closed'] = 0

    def scan(self, service: List) -> None:
        """Scan a port."""
        sock = socket.socket(self.family, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        if not sock.connect_ex((self.args.target, service[1])):
            log.log(f'Port {service[1]} {service[0]} opened', log.SUCCESS)
            self.results['opened'] += 1
        else:
            log.log(f'Port {service[1]} closed', log.FAILURE, 1, self.verbosity)
            self.results['closed'] += 1
        sock.close()

        self.pool.release()
