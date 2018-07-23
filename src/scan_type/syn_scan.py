"""
    A module docstring.
"""

import threading
from typing import List

from scapy.all import *

from .. import app


class SynScan(threading.Thread):
    """docstring for SynScan"""
    def __init__(self, pool: threading.BoundedSemaphore,
                 service: List) -> None:

        super(SynScan, self).__init__()

        self.pool = pool
        self.service = service

        self.flag = app.flag

    @staticmethod
    def init() -> None:
        """Initialize some variables."""
        app.results['opened'] = 0
        app.results['closed'] = 0
        app.results['filtered'] = 0

    def run(self) -> None:
        """Scan a port."""
        target = IP(dst=app.args.target) / TCP(flags=self.flag, dport=self.service[1])
        res = sr1(target, timeout=app.timeout)
        if res is None:
            app.results['filtered'] += 1
            app.xprint(f'Port {self.service[1]} filtered', 3, app.SUCCESS)
        elif 'ICMP' in res:
            if res['ICMP'].type == 3 and res['ICMP'].code in [0, 1, 2, 9, 10, 13]:
                app.results['filtered'] += 1
                app.xprint(f'Port {self.service[1]} filtered', app.INFORMATION)
            else:
                app.xprint('error #1')
        elif 'TCP' in res:
            if res['TCP'].flags & app.TCP.SYN:
                app.results['opened'] += 1
                app.xprint(f'Port {self.service[1]} {self.service[0]} opened', app.INFORMATION)
                seq = res.seq + 1
                target = IP(dst=app.args.target) / TCP(flags='R', dport=self.service[1], seq=seq)
                send(target)
            elif res['TCP'].flags & app.TCP.RST:
                app.results['closed'] += 1
                app.xprint(f'Port {self.service[1]} closed', 2, app.SUCCESS)
            else:
                app.xprint('error #2')
        else:
            app.xprint('error #3')

        self.pool.release()
