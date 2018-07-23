"""
    A module docstring.
"""

import threading
import socket
from typing import List

from .. import app


class ConnectScan(threading.Thread):
    """docstring for ConnectScan"""
    def __init__(self, pool: threading.BoundedSemaphore,
                 service: List) -> None:

        super(ConnectScan, self).__init__()

        self.pool = pool
        self.service = service

        if app.ipv6:
            self.family = socket.AF_INET6
        else:
            self.family = socket.AF_INET

    @staticmethod
    def init() -> None:
        """Initialize some variables."""
        app.results['opened'] = 0
        app.results['closed'] = 0

    def run(self) -> None:
        """Scan a port."""
        sock = socket.socket(self.family, socket.SOCK_STREAM)
        sock.settimeout(app.timeout)
        if not sock.connect_ex((app.args.target, self.service[1])):
            app.xprint(f'Port {self.service[1]} {self.service[0]} opened', app.SUCCESS)
            app.results['opened'] += 1
        else:
            app.xprint(f'Port {self.service[1]} closed', 2, app.SUCCESS)
            app.results['closed'] += 1
        sock.close()

        self.pool.release()
