"""
    A module docstring.
"""

import threading
from typing import List

from scapy.all import *

from .. import app


class AckScan(threading.Thread):
    """docstring for AckScan"""
    def __init__(self, pool: threading.BoundedSemaphore,
                 service: List) -> None:

        super(AckScan, self).__init__()

        self.pool = pool
        self.service = service

    @staticmethod
    def init() -> None:
        """Initialize some variables."""
        app.results['filtered'] = 0
        app.results['unfiltered'] = 0

    def run(self) -> None:
        """Scan a port."""
        target = IP(dst=app.args.target) / TCP(flags='A', dport=self.service[1])
        res = sr1(target, timeout=app.timeout, verbose=0)
        if res is None:
            app.results['filtered'] += 1
            app.xprint(f'Port {self.service[1]} filtered', app.INFORMATION)
        elif 'ICMP' in res:
            if res['ICMP'].type == 3 and res['ICMP'].code in [0, 1, 2, 9, 10, 13]:
                app.results['filtered'] += 1
                app.xprint(f'Port {self.service[1]} filtered', app.INFORMATION)
            else:
                app.xprint('error #9')
        elif 'TCP' in res:
            if res['TCP'].flags & app.TCP.RST:
                app.results['unfiltered'] += 1
                app.xprint(f'Port {self.service[1]} unfiltered', app.SUCCESS, 3, self.scan.verbosity)
        else:
            app.xprint('error #10')

        self.pool.release()
