"""
    A module docstring.
"""

import threading
from typing import List

from scapy.all import *

from .. import app


class FinScan(threading.Thread):
    """docstring for FinScan"""
    def __init__(self, pool: threading.BoundedSemaphore,
                 service: List) -> None:

        super(FinScan, self).__init__()

        self.pool = pool
        self.service = service

        self.flag = app.flag

    @staticmethod
    def init() -> None:
        """Initialize some variables."""
        app.results['closed'] = 0
        app.results['filtered'] = 0
        app.results['openedFiltered'] = 0

    def run(self) -> None:
        """Scan a port."""
        target = IP(dst=app.args.target) / TCP(flags=self.flag, dport=self.service[1])
        res = sr1(target, timeout=app.timeout, verbose=0)
        if res is None:
            app.results['openedFiltered'] += 1
            app.xprint(f'Port {self.service[1]} opened|filtered', 2, app.SUCCESS)
        elif 'TCP' in res:
            if res['TCP'].flags & app.TCP.RST:
                app.results['closed'] += 1
                app.xprint(f'Port {self.service[1]} {self.service[0]} closed', app.FAILURE)
            else:
                app.xprint('error #4')
        elif 'ICMP' in res:
            if res['ICMP'].type == 3 and res['ICMP'].code in [0, 1, 2, 9, 10, 13]:
                app.results['filtered'] += 1
                app.xprint(f'Port {self.service[1]} filtered', app.INFORMATION)
            else:
                app.xprint('error #5')
        else:
            app.xprint('error #6')

        self.pool.release()
