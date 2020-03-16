"""
    A module docstring.
"""

from typing import List, Any, Dict
from datetime import datetime
import threading
import socket
import abc
import argparse

from .config import arguments
from . import app, log
from .ip import IP


NOT_STARTED = 0
STARTED = 1
ENDED = 2


class Scan(threading.Thread):
    """docstring for Scan"""
    __metaclass__ = abc.ABCMeta

    MAXTHREAD = 5  # TODO: modify MAXTHREAD dynamicaly

    def __init__(self, args: argparse.Namespace = None) -> None:
        super(Scan, self).__init__()

        self.pool = threading.BoundedSemaphore(value=self.MAXTHREAD)
        self.results: Dict[str, Any] = {}
        self.scan_status = NOT_STARTED

        if not app.is_tool('nmap'):
            raise OSError('Nmap is required to use this script.')

        # conf.verb = 0  # Disable verbosity output from scapy
        # FIXME: ^

        # ARGS PARSING
        if args is not None:
            self.args = args
        else:
            self.args = arguments()

        self.verbosity = self.args.verbosity

        if IP.is_ipv6(self.args.target):
            self.ipv6 = True
            self.hostip = self.args.target
        else:
            self.ipv6 = False
            try:
                self.hostip = socket.gethostbyname(self.args.target)
            except socket.gaierror:
                raise ValueError("Not a correct IP/FQDN.")

        # timeout (en seconde)
        # TODO: modify timeout dynamicaly
        if IP.is_private(self.hostip):
            self.timeout = 0.1
        else:
            self.timeout = 0.5

    def run(self) -> None:
        """Run the scan."""
        threads: List[threading.Thread] = []
        self.scan_status = STARTED

        # We start all the thread
        for service in self.port_list:
            self.pool.acquire()
            scanport = threading.Thread(target=self.scan, args=(service,))
            scanport.start()
            threads.append(scanport)

        # We wait the end of all threads
        for thread in threads:
            thread.join()

        self.scan_status = ENDED

    def get_status(self, start_time: datetime = None) -> str:
        """Display the actual status of the scan."""
        out = ''

        for key in self.results:
            if key is not None:
                out += f'{log.Colors.information} {self.results[key]} ports {key}\n'

        if start_time is not None:
            out += f'{log.Colors.information} Duration : {datetime.now() - start_time}\n'

        return out

    def info(self) -> None:
        """Display some informations about the scan."""
        out = ''

        out += f'Scan for {self.args.target} with IP {self.hostip}\n'

        if self.scan_status is NOT_STARTED:
            out += f'Scan: {log.Colors.red}NOT STARTED{log.Colors.end}\n'
        elif self.scan_status is STARTED:
            out += f'Scan: {log.Colors.blue}STARTED{log.Colors.end}\n'
            out += self.get_status()
        elif self.scan_status is ENDED:
            out += f'Scan: {log.Colors.green}ENDED{log.Colors.end}\n'
            out += self.get_status()
        else:
            raise Exception(f'Scan\'s status not implemented: {self.scan_status}')

        log.log(out, log.INFORMATION)

    @abc.abstractmethod
    def scan(self, service: List) -> None:
        """Scan a port."""
        raise NotImplementedError('Must override scan.')
