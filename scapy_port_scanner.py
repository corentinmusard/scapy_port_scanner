#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import socket
import sys
import argparse
from scapy.all import *
import time
from datetime import datetime
import threading


SUCCESS = 1
FAILURE = 2
INFORMATION = 3


def is_tool(name):
    """Check whether `name` is on PATH and marked as executable."""
    from shutil import which
    return which(name) is not None


def xprint(content="", design=0, verbosity=0):
    """Print strings to stdout."""
    begin = ''
    if design == 1:
        begin = colors.success
    elif design == 2:
        begin = colors.failure
    elif design == 3:
        begin = colors.information

    if args.verbosity >= verbosity:
        sys.stdout.write(begin + content + '\n')
        sys.stdout.flush()


def arguments():
    """Parse the command line arguments."""
    global args

    parser = argparse.ArgumentParser(
        prog='scapy_port_scanner.py', description='Port scanner',
        epilog='/!\\ Nmap and scapy are required to use this script')

    parser.add_argument(
        '-t', '--target', type=str, metavar='target', default='localhost',
        help='The target to scan')
    parser.add_argument(
        '-v6', '--ipv6', action='store_true', help='Use IPv6 address (only working with the connect scan)')
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


def colors():
    """Constants for coloring output."""
    colors.red = '\033[1;31m'
    colors.green = '\033[1;32m'
    colors.blue = '\033[1;34m'
    colors.end = '\033[0m'

    colors.success = colors.green + '[+]' + colors.end + ' '
    colors.failure = colors.red + '[-]' + colors.end + ' '
    colors.information = colors.blue + '[*]' + colors.end + ' '


def TCP_flags():
    """Constants TCP flags value."""
    TCP_flags.FIN = 0x01
    TCP_flags.SYN = 0x02
    TCP_flags.RST = 0x04
    TCP_flags.PSH = 0x08
    TCP_flags.ACK = 0x10
    TCP_flags.URG = 0x20
    TCP_flags.ECE = 0x40
    TCP_flags.CWR = 0x80


class start_thread(threading.Thread):
    """Start the scan's threads."""
    def __init__(self, **kwargs):
        threading.Thread.__init__(self)
        for key, value in kwargs.items():
            setattr(self, key, value)

    def run(self):
        if not hasattr(self, 'family'):
            self.family = ''
        if not hasattr(self, 'flag'):
            self.flag = ''

        for service in self.port_list:
            pool.acquire()
            scanport = getattr(sys.modules[__name__], self.t + 'Thread')(service, flag=self.flag, family=self.family)
            scanport.setDaemon(True)
            scanport.start()
            scanport.join()


class connectThread(threading.Thread):
    """Run the connect scan."""
    def __init__(self, service, **kwargs):
        threading.Thread.__init__(self)
        self.service = service
        for key, value in kwargs.items():
            setattr(self, key, value)

    def run(self):
        global opened, closed
        s = socket.socket(self.family, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if not s.connect_ex((args.target, self.service[1])):
            xprint("Port {} {} opened".format(self.service[1], self.service[0]), SUCCESS)
            opened += 1
        else:
            xprint("Port {} closed".format(self.service[1]), 2, SUCCESS)
            closed += 1
        s.close()
        pool.release()


def connect_scan_config():
    """Configure parameters for the scan, then call the function to begin the scan."""
    xprint("Starting Connect Scan", INFORMATION)
    if args.ipv6:
        family = socket.AF_INET6
    else:
        family = socket.AF_INET

    port_list = most_used_ports()

    handler = start_thread(port_list=port_list, family=family, t='connect')
    handler.start()
    handler.join()


class SynThread(threading.Thread):
    """Run the SYN scan."""
    def __init__(self, service, **kwargs):
        threading.Thread.__init__(self)
        self.service = service
        for key, value in kwargs.items():
            setattr(self, key, value)

    def run(self):
        global opened, closed, filtered
        target = IP(dst=args.target) / TCP(flags=self.flag, dport=self.service[1])
        res = sr1(target, timeout=timeout, verbose=0)
        if res is None:
            filtered += 1
            xprint("Port {} filtered".format(self.service[1]), 3, SUCCESS)
        elif 'ICMP' in res:
            if res['ICMP'].type == 3 and res['ICMP'].code in [0, 1, 2, 9, 10, 13]:
                filtered += 1
                xprint("Port {} filtered".format(self.service[1]), INFORMATION)
            else:
                xprint('error #1')
        elif 'TCP' in res:
            if res['TCP'].flags & TCP_flags.SYN:
                opened += 1
                xprint("Port {} {} opened".format(self.service[1], self.service[0]), INFORMATION)
                seq = res.seq + 1
                target = IP(dst=args.target) / TCP(flags='R', dport=self.service[1], seq=seq)
                send(target)
            elif res['TCP'].flags & TCP_flags.RST:
                closed += 1
                xprint("Port {} closed".format(self.service[1]), 2, SUCCESS)
            else:
                xprint('error #2')
        else:
            xprint('error #3')
        pool.release()


def syn_scan_config(flag):
    """Configure parameters for the scan, then call the function to begin the scan."""
    xprint("Starting SYN Scan", INFORMATION)
    port_list = most_used_ports()
    handler = start_thread(port_list=port_list, flag=flag, t='Syn')
    handler.start()
    handler.join()


class FinThread(threading.Thread):
    """Run the FIN scan."""
    def __init__(self, service, **kwargs):
        threading.Thread.__init__(self)
        self.service = service
        for key, value in kwargs.items():
            setattr(self, key, value)

    def run(self):
        global closed, filtered, openedFiltered
        target = IP(dst=args.target) / TCP(flags=self.flag, dport=self.service[1])
        res = sr1(target, timeout=timeout, verbose=0)
        if res is None:
            openedFiltered += 1
            xprint("Port {} opened|filtered".format(self.service[1]), 2, SUCCESS)
        elif 'TCP' in res:
            if res['TCP'].flags & TCP_flags.RST:
                closed += 1
                xprint("Port {} {} closed".format(self.service[1], self.service[0]), FAILURE)
            else:
                xprint('error #4')
        elif 'ICMP' in res:
            if res['ICMP'].type == 3 and res['ICMP'].code in [0, 1, 2, 9, 10, 13]:
                filtered += 1
                xprint("Port {} filtered".format(self.service[1]), INFORMATION)
            else:
                xprint('error #5')
        else:
            xprint('error #6')
        pool.release()


def fin_scan_config(flag):
    """Configure parameters for the scan, then call the function to begin the scan."""
    xprint("Starting FIN Scan", INFORMATION)
    port_list = most_used_ports()
    handler = start_thread(port_list=port_list, flag=flag, t='Fin')
    handler.start()
    handler.join()


class UdpThread(threading.Thread):
    """Run the UDP scan."""
    def __init__(self, service, **kwargs):
        threading.Thread.__init__(self)
        self.service = service
        for key, value in kwargs.items():
            setattr(self, key, value)

    def run(self):
        global opened, closed, filtered, openedFiltered
        target = IP(dst=args.target) / UDP(dport=self.service[1])
        res = sr1(target, timeout=timeout, verbose=0)
        if res is None:
            openedFiltered += 1
            xprint("Port {} opened|filtered".format(self.service[1]), FAILURE)
        elif 'ICMP' in res:
            if res['ICMP'].type == 3 and res['ICMP'].code == 3:
                closed += 1
                xprint("Port {} closed".format(self.service[1]), 2, SUCCESS)
                time.sleep(0.9)
            elif res['ICMP'].type == 3 and res['ICMP'].code in [0, 1, 2, 9, 10, 13]:
                filtered += 1
                xprint("Port {} filtered".format(self.service[1]), INFORMATION)
            else:
                xprint('error #7')
        elif 'UDP' in res:
            opened += 1
            xprint("Port {} {} opened".format(self.service[1], self.service[0]), SUCCESS)
        else:
            xprint('error #8')
        pool.release()


def udp_scan_config():
    """Configure parameters for the scan, then call the function to begin the scan."""
    xprint("Starting UDP Scan", INFORMATION)
    port_list = most_used_ports('udp')
    handler = start_thread(port_list=port_list, t='Udp')
    handler.start()
    handler.join()


class AckThread(threading.Thread):
    """Run the ACK scan."""
    def __init__(self, service, **kwargs):
        threading.Thread.__init__(self)
        self.service = service
        for key, value in kwargs.items():
            setattr(self, key, value)

    def run(self):
        global filtered, unfiltered
        target = IP(dst=args.target) / TCP(flags='A', dport=self.service[1])
        res = sr1(target, timeout=timeout, verbose=0)
        if res is None:
            filtered += 1
            xprint("Port {} filtered".format(self.service[1]), INFORMATION)
        elif 'ICMP' in res:
            if res['ICMP'].type == 3 and res['ICMP'].code in [0, 1, 2, 9, 10, 13]:
                filtered += 1
                xprint("Port {} filtered".format(self.service[1]), INFORMATION)
            else:
                xprint('error #9')
        elif 'TCP' in res:
            if res['TCP'].flags & TCP_flags.RST:
                unfiltered += 1
                xprint("Port {} unfiltered".format(self.service[1]), 3, SUCCESS)
        else:
            xprint('error #10')
        pool.release()


def ack_scan_config():
    """Configure parameters for the scan, then call the function to begin the scan."""
    xprint("Starting ACK Scan", INFORMATION)
    port_list = most_used_ports()
    handler = start_thread(port_list=port_list, t='Ack')
    handler.start()
    handler.join()


def scanflags():
    """Return the flags desired from the command line argument --scanflags."""
    flag = ''
    if 'FIN' in args.scanflags:
        flag += 'F'
    if 'SYN' in args.scanflags:
        flag += 'S'
    if 'RST' in args.scanflags:
        flag += 'R'
    if 'PSH' in args.scanflags:
        flag += 'P'
    if 'ACK' in args.scanflags:
        flag += 'A'
    if 'URG' in args.scanflags:
        flag += 'U'
    if 'ECE' in args.scanflags:
        flag += 'E'
    if 'CWR' in args.scanflags:
        flag += 'C'
    return flag


def getFreq(item):
    """Return the open's frequence of the desired service."""
    return item[3]


def most_used_ports(proto='tcp'):
    """Parse the nmap's service file and Return the most used ports."""
    # TODO: add random options
    # TODO: remove the nmap's dependences
    with open('/usr/share/nmap/nmap-services', 'r') as f:
        D = []
        for line in f:
            if line.startswith('#'):
                continue

            protocol = line.split()[1].split('/')[1]
            if protocol == proto:
                name = line.split()[0]
                port = line.split()[1].split('/')[0]
                freq = line.split()[2]
                D.append([name, int(port), protocol, freq])

        D = sorted(D, key=getFreq, reverse=True)
        if args.all_ports:
            return D
        else:
            return D[:args.top_ports]


def check_ip():
    """Look the ip from -t argument and
    Set the timeout for the scan weither it's a public or a private ip.
    """
    # TODO: ipv6 support
    # TODO: gestion of urls
    global timeout
    ip = config.hostip

    if args.ipv6:
        timeout = 0.5
    else:
        ip = ip.split('.')
        if ((ip[0] == '10') or
                (ip[0] == '172' and ip[1] <= '31' and ip[1] >= '16') or
                (ip[0] == '192' and ip[1] == '168')):

            timeout = 0.1
        else:
            timeout = 0.5


def config():
    """Set various variables."""
    arguments()

    # Nmap is required to use this script
    if not is_tool('nmap'):
        xprint('Nmap is required to use this script', FAILURE)
        exit()

    try:
        config.hostip = socket.gethostbyname(args.target)
    except Exception:
        exit("Not a correct IP/FQDN.")

    check_ip()

    colors()
    TCP_flags()

    conf.verb = 0  # Disable verbosity output from scapy

    global opened, closed, filtered, openedFiltered, unfiltered
    opened = closed = filtered = openedFiltered = unfiltered = 0

    MAXTHREAD = 10

    global pool
    pool = threading.BoundedSemaphore(value=MAXTHREAD)


def main():
    start_time = datetime.now()
    config()

    xprint("Scan for {} with IP: {}".format(args.target, config.hostip), INFORMATION)

    if args.sC:
        connect_scan_config()
    elif args.sU:
        udp_scan_config()
    elif args.sS:
        syn_scan_config('S')
    elif args.sF:
        fin_scan_config('F')
    elif args.sN:
        fin_scan_config('')
    elif args.sX:
        fin_scan_config('FPU')
    elif args.sA:
        ack_scan_config()
    elif args.scanflags:
        flag = scanflags()
        xprint("Starting scan with flag : {}".format(flag), INFORMATION)
        syn_scan(flag)
    else:
        xprint("No scan type choosed", INFORMATION)
        exit()

    nbscanned = opened + openedFiltered + closed + filtered + unfiltered
    xprint()
    xprint("{} ports scanned".format(nbscanned), INFORMATION)

    if opened != 0:
        xprint("{} ports opened".format(opened), INFORMATION)

    if openedFiltered != 0:
        xprint("{} ports opened|filtered".format(openedFiltered), INFORMATION)

    if closed != 0:
        xprint("{} ports closed".format(closed), INFORMATION)

    if filtered != 0:
        xprint("{} ports filtered".format(filtered), INFORMATION)

    if unfiltered != 0:
        xprint("{} ports unfiltered".format(unfiltered), INFORMATION)

    xprint("Duration : {}".format(datetime.now() - start_time), INFORMATION)


if __name__ == '__main__':
    main()
