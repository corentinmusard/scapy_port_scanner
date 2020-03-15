"""
    A module docstring.
"""

from typing import Optional
import argparse

from .config import arguments
from . import app
from .scan_type import *
from .scan import Scan


class ScanFinder:
    """docstring for ScanFinder"""
    def __init__(self) -> None:
        self.args = argparse.Namespace()

    def find_type(self) -> Optional[str]:
        """Find the type of the scan.
        It's based on the argumements from the command line.
        """
        self.args = arguments()

        if self.args.sC:
            scan_name = 'connect'
        elif self.args.sU:
            scan_name = 'udp'
        elif self.args.sS:
            scan_name = 'syn'
        elif self.args.sF:
            scan_name = 'fin'
        elif self.args.sN:
            scan_name = 'fin'
        elif self.args.sX:
            scan_name = 'fin'
        elif self.args.sA:
            scan_name = 'ack'
        elif self.args.scanflags:
            scan_name = 'syn'
        else:
            app.xprint('No scan type choosed, try --help for more information.')
            return None

        return scan_name

    def get_scan(self, scan_name: str) -> Optional[Scan]:
        """Return the scan related to `scan_name`.
        Return None if no scan is found.
        """
        try:
            scan = globals()[scan_name.capitalize() + 'Scan'](self.args)
        except KeyError:
            return None
        else:
            return scan
