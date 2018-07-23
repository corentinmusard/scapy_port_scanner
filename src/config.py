"""
    A module docstring.
"""

import argparse
import socket
from typing import Any

from scapy.all import *

from . import app


def config() -> Any:  # TOFIX le type de retour
    """Set various variables.
       And configure few thing.
    """
    args = arguments()
    app.args = args

    # Nmap is required to use this script
    if not app.is_tool('nmap'):
        app.xprint('Nmap is required to use this script.', app.FAILURE)
        exit()

    conf.verb = 0  # Disable verbosity output from scapy

    # ARGS PARSING

    if app.IP.is_ipv6(args.target):
        app.ipv6 = True
        hostip = args.target
    else:
        try:
            hostip = socket.gethostbyname(args.target)
        except socket.gaierror:
            exit("Not a correct IP/FQDN.")

    # timeout (en seconde)
    # TODO: modify timeout dynamicaly
    if app.IP.is_private(hostip):
        app.timeout = 0.1
    else:
        app.timeout = 0.5

    if args.sU:
        port_list = app.most_used_ports('udp', args.top_ports)
    else:
        port_list = app.most_used_ports('tcp', args.top_ports)

    flag = ''

    if args.sC:
        scan_type = 'connect'
    elif args.sU:
        scan_type = 'udp'
    elif args.sS:
        scan_type = 'syn'
        flag = 'S'
    elif args.sF:
        scan_type = 'fin'
        flag = 'F'
    elif args.sN:
        scan_type = 'fin'
        flag = ''
    elif args.sX:
        scan_type = 'fin'
        flag = 'FPU'
    elif args.sA:
        scan_type = 'ack'
    elif args.scanflags:
        scan_type = 'syn'
        flag = app.TCP.scanflags(args.scanflags)
        app.xprint(f'Starting scan with flag : {flag}')
    else:
        app.xprint('No scan type choosed, try --help for more information.')
        exit()

    app.flag = flag

    return (port_list, hostip, scan_type)


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
    scan.add_argument(
        '-sU', action='store_true', help='UDP Scan')
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
