"""
    A module docstring.
"""

import argparse


def arguments() -> argparse.Namespace:
    """Parse the command line arguments."""
    parser = argparse.ArgumentParser(
        prog='scapy_port_scanner.py', description='Port scanner',
        epilog='/!\\ Nmap and scapy are required to use this script')

    parser.add_argument(
        '-t', '--target', type=str, metavar='target', default='localhost',
        help='The target to scan')
    parser.add_argument(
        '-v', '--verbosity', action='count', default=0,
        help='The verbosity level, use -vv or more')
    parser.add_argument(
        '--top-ports', type=int, metavar='N', default='1000',
        help='The N most common port to scan')
    parser.add_argument(
        '-p-', dest='all_ports', action='store_true',
        help='Scan all ports (only the most common from the nmap list not 65535 ports)')
    parser.add_argument(
        '--version', action='version', version='%(prog)s v0.1.0')

    scan = parser.add_argument_group('SCANNING TECHNIQUES')
    scan = scan.add_mutually_exclusive_group()
    scan.add_argument('-sU', action='store_true', help='UDP Scan')
    scan.add_argument(
        '-sC', action='store_true', help="Connect Scan")
    scan.add_argument(
        '-sS', action='store_true', help="SYN Scan")
    scan.add_argument(
        '-sF', action='store_true', help="FIN Scan")
    scan.add_argument(
        '-sN', action='store_true', help="NULL Scan")
    scan.add_argument(
        '-sX', action='store_true', help="Xmas Scan")
    scan.add_argument(
        '-sA', action='store_true', help="ACK Scan")
    scan.add_argument(
        '--scanflags', type=str, help='The TCP flag to use for a SYN scan')

    args = parser.parse_args()

    print(args)
    return args
