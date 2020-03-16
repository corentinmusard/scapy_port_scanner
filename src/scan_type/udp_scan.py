"""
    A module docstring.
"""

import threading
from typing import List
import time
import argparse

from scapy.all import *

from .. import app, log
from .. import tcp
from ..scan import Scan


class UdpScan(Scan):
    """docstring for UdpScan"""
    def __init__(self, args: argparse.Namespace = None) -> None:
        super(UdpScan, self).__init__(args)

        self.port_list = app.most_used_ports('tcp', self.args.top_ports)
        self.flag = 'S'

        self.results['opened'] = 0
        self.results['closed'] = 0
        self.results['filtered'] = 0
        self.results['openedFiltered'] = 0

        conf.verb = 0  # Disable verbosity output from scapy

    def scan(self, service: List) -> None:
        """Scan a port."""
        target = IP(dst=self.args.target) / UDP(dport=service[1])
        res = sr1(target, timeout=self.timeout, verbose=0)
        if res is None:
            self.results['openedFiltered'] += 1
            log.log(f'Port {service[1]} opened|filtered', log.FAILURE, 1, self.verbosity)
        elif 'ICMP' in res:
            if res['ICMP'].type == 3 and res['ICMP'].code == 3:
                self.results['closed'] += 1
                log.log(f'Port {service[1]} closed', log.SUCCESS, 2, self.verbosity)
                time.sleep(0.9)
            elif res['ICMP'].type == 3 and res['ICMP'].code in [0, 1, 2, 9, 10, 13]:
                self.results['filtered'] += 1
                log.log(f'Port {service[1]} filtered', log.INFORMATION, 1, self.verbosity)
            else:
                log.log('error #7')
        elif 'UDP' in res:
            self.results['opened'] += 1
            log.log(f'Port {service[1]} {service[0]} opened', log.SUCCESS)
        else:
            log.log('error #8')

        self.pool.release()
