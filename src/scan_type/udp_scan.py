"""
    A module docstring.
"""

import threading
from typing import List
import time

from scapy.all import *

from .. import app


class UdpScan(threading.Thread):
    """docstring for UdpScan"""
    def __init__(self, pool: threading.BoundedSemaphore,
                 service: List) -> None:

        super(UdpScan, self).__init__()

        self.pool = pool
        self.service = service

    @staticmethod
    def init() -> None:
        """Initialize some variables."""
        app.results['opened'] = 0
        app.results['closed'] = 0
        app.results['filtered'] = 0
        app.results['openedFiltered'] = 0

    def run(self) -> None:
        """Scan a port."""
        target = IP(dst=app.args.target) / UDP(dport=self.service[1])
        res = sr1(target, timeout=app.timeout, verbose=0)
        if res is None:
            app.results['openedFiltered'] += 1
            app.xprint(f'Port {self.service[1]} opened|filtered', 1, app.FAILURE)
        elif 'ICMP' in res:
            if res['ICMP'].type == 3 and res['ICMP'].code == 3:
                app.results['closed'] += 1
                app.xprint(f'Port {self.service[1]} closed', 2, app.SUCCESS)
                time.sleep(0.9)
            elif res['ICMP'].type == 3 and res['ICMP'].code in [0, 1, 2, 9, 10, 13]:
                app.results['filtered'] += 1
                app.xprint(f'Port {self.service[1]} filtered', 1, app.INFORMATION)
            else:
                app.xprint('error #7')
        elif 'UDP' in res:
            app.results['opened'] += 1
            app.xprint(f'Port {self.service[1]} {self.service[0]} opened', app.SUCCESS)
        else:
            app.xprint('error #8')

        self.pool.release()
