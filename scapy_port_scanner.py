#!/usr/bin/env python
"""
    A module docstring.
"""

from datetime import datetime

from src import *


def main() -> None:
    """Main function of scapy_port_scanner"""
    start_time = datetime.now()

    (port_list, hostip, scan_type) = config()

    app.xprint(f'Scan for {app.args.target} with IP {hostip}', app.INFORMATION)

    scan = Scan(scan_type, port_list)
    scan.start()  # Start the scan with thread
    scan.join()  # Wait the end of all thread

    app.end(start_time)


if __name__ == '__main__':
    main()
