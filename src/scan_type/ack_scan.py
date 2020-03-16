"""
    A module docstring.
"""

import threading
import argparse
from typing import List

from scapy.all import *

from .. import app, log
from .. import tcp
from ..scan import Scan


class AckScan(Scan):
    """docstring for AckScan"""
    def __init__(self, args: argparse.Namespace = None) -> None:
        super(AckScan, self).__init__(args)

        self.port_list = app.most_used_ports('tcp', self.args.top_ports)
        self.flag = 'A'

        self.results['filtered'] = 0
        self.results['unfiltered'] = 0

        conf.verb = 0  # Disable verbosity output from scapy

    def scan(self, service: List) -> None:
        """Scan a port."""
        target = IP(dst=self.args.target) / TCP(flags=self.flag, dport=service[1])
        res = sr1(target, timeout=self.timeout, verbose=0)
        if res is None:
            self.results['filtered'] += 1
            log.log(f'Port {service[1]} filtered', log.INFORMATION)
        elif 'ICMP' in res:
            if res['ICMP'].type == 3 and res['ICMP'].code in [0, 1, 2, 9, 10, 13]:
                self.results['filtered'] += 1
                log.log(f'Port {service[1]} filtered', log.INFORMATION)
            else:
                log.log('error #9')
        elif 'TCP' in res:
            if res['TCP'].flags & tcp.TCP.RST:
                self.results['unfiltered'] += 1
                log.log(f'Port {service[1]} unfiltered', log.SUCCESS, 3, self.verbosity)
        else:
            log.log('error #10')

        self.pool.release()
