"""
    A module docstring.
"""

import threading
from typing import List, Iterator

from .scan_type import *


class Scan(threading.Thread):
    """docstring for Scan"""

    MAXTHREAD = 5  # TODO: modify MAXTHREAD dynamicaly

    def __init__(self, scan_name: str, port_list: Iterator[List]) -> None:
        super(Scan, self).__init__()
        self.scan_name = scan_name.capitalize() + 'Scan'
        self.pool = threading.BoundedSemaphore(value=self.MAXTHREAD)
        self.port_list = port_list

    def run(self) -> None:
        """Run the scan """
        globals()[self.scan_name].init()  # Initialisation of the scan's thread
        threads: List[threading.Thread] = []

        # We start all the thread
        for service in self.port_list:
            self.pool.acquire()
            scanport = globals()[self.scan_name](self.pool, service)
            scanport.start()
            threads.append(scanport)

        # We wait the end of all threads
        for thread in threads:
            thread.join()
