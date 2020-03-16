"""
    A module docstring.
"""

from typing import List
import argparse

from scapy.all import *

from .. import app, log
from .. import tcp
from ..scan import Scan


class SynScan(Scan):
    """docstring for SynScan"""
    def __init__(self, args: argparse.Namespace = None) -> None:
        super(SynScan, self).__init__(args)

        self.port_list = app.most_used_ports('tcp', self.args.top_ports)
        self.flag = 'S'

        self.results['opened'] = 0
        self.results['closed'] = 0
        self.results['filtered'] = 0

        conf.verb = 0  # Disable verbosity output from scapy

    def scan(self, service: List) -> None:
        """Scan a port."""
        target = IP(dst=self.args.target) / TCP(flags=self.flag, dport=service[1])
        res = sr1(target, timeout=self.timeout)
        if res is None:
            self.results['filtered'] += 1
            log.log(f'Port {service[1]} filtered', log.SUCCESS, 3, self.verbosity)
        elif 'ICMP' in res:
            if res['ICMP'].type == 3 and res['ICMP'].code in [0, 1, 2, 9, 10, 13]:
                self.results['filtered'] += 1
                log.log(f'Port {service[1]} filtered', log.INFORMATION)
            else:
                log.log('error #1')
        elif 'TCP' in res:
            if res['TCP'].flags & tcp.TCP.SYN:
                self.results['opened'] += 1
                log.log(f'Port {service[1]} {service[0]} opened', log.INFORMATION)
                seq = res.seq + 1
                target = IP(dst=self.args.target) / TCP(flags='R', dport=service[1], seq=seq)
                send(target)
            elif res['TCP'].flags & tcp.TCP.RST:
                self.results['closed'] += 1
                log.log(f'Port {service[1]} closed', log.SUCCESS, 2, self.verbosity)
            else:
                log.log('error #2')
        else:
            log.log('error #3')

        self.pool.release()
