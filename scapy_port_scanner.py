#!/usr/bin/env python
"""
    A module docstring.
"""

from src import ScanFinder


def main() -> None:
    """Main function of scapy_port_scanner"""
    scan_finder = ScanFinder()
    scan_name = scan_finder.find_type()

    if scan_name is None:
        print('Scan\'s name not found.')
        exit()

    scan = scan_finder.get_scan(scan_name)

    if scan is None:
        print('Scan not found.')
        exit()

    scan.start()  # Start the scan with thread
    scan.join()  # Wait the end of all thread
    scan.info()  # Print some info about the scan


if __name__ == '__main__':
    main()
