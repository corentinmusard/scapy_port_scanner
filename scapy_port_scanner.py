#!/usr/bin/env python3.4
# -*- coding: UTF-8 -*-

import socket
import sys
import argparse
from scapy.all import *
import time
from datetime import datetime
import threading
import logging
import random

def is_tool(name):
    #Check whether `name` is on PATH and marked as executable.
    from shutil import which
    return which(name) is not None

def xprint(content, design=0, verbosity=0):
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
    global args

    parser = argparse.ArgumentParser(
    prog='scapy_port_scanner.py', description='Port scanner',
    epilog='/!\ Nmap and scapy are required to use this script')

    parser.add_argument(
        '-t', '--target', type=str, metavar='target', default='localhost', help='The target to scan')
    parser.add_argument(
        '-v6', '--ipv6', action='store_true', help='Use IPv6 address')
    parser.add_argument(
        '-v', '--verbosity', action='count', default=0, help='The verbosity level, use -vv or more')
    parser.add_argument(
        '--top-ports', type=int, metavar='N', default='1000', help='The N most common port to scan')
    parser.add_argument(
        '-p-', dest='all_ports', action='store_true', help='Scan all ports (65535 ports)')
    parser.add_argument(
        '--version', action='version', version='%(prog)s v0.1')

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
    colors.red = '\033[1;31m'
    colors.green = '\033[1;32m' 
    colors.blue = '\033[1;34m'
    colors.end = '\033[0m'

    colors.success = colors.green + '[+]' + colors.end + ' '
    colors.failure = colors.red + '[-]' + colors.end + ' '
    colors.information = colors.blue + '[*]' + colors.end + ' '

def TCP_flags():
    TCP_flags.FIN = 0x01
    TCP_flags.SYN = 0x02
    TCP_flags.RST = 0x04
    TCP_flags.PSH = 0x08
    TCP_flags.ACK = 0x10
    TCP_flags.URG = 0x20
    TCP_flags.ECE = 0x40
    TCP_flags.CWR = 0x80

class GrabUrl(threading.Thread):
    def __init__(self, service, family):
        threading.Thread.__init__(self)
        self.service = service
        self.family = family
    def run(self):
        global opened, closed
        s = socket.socket(self.family, socket.SOCK_STREAM)
        s.settimeout(timeout)

        if not s.connect_ex((args.target, self.service[1])):
            xprint("Port {} {} opened".format(self.service[1], self.service[0]), 1)
            opened += 1
        else:
            xprint("Port {} closed".format(self.service[1]), 2, 1)
            closed += 1
        s.close()
        pool.release()

class scanThread(threading.Thread):
    def __init__(self,port_list, family):
        threading.Thread.__init__(self)
        self.port_list = port_list
        self.family = family
    def run(self):
        for i in self.port_list:
            pool.acquire()
            graburl=GrabUrl(i, self.family)
            graburl.setDaemon(True)
            graburl.start()

def connect_scan():
    xprint("Starting Connect Scan", 3)
    if args.ipv6:
        family = socket.AF_INET6
    else:
        family = socket.AF_INET

    port_list = most_used_ports()
    
    handler=scanThread(port_list, family)
    handler.start()
    handler.join()

def connect_scan_old():
    xprint("Starting Connect Scan", 3)
    global opened, closed
    if args.ipv6:
        family = socket.AF_INET6
    else:
        family = socket.AF_INET

    port_list = most_used_ports()
    for service in port_list:
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(timeout)

        if not s.connect_ex((args.target, service[1])):
            xprint("Port {} {} opened".format(service[1], service[0]), 1)
            opened += 1
        else:
            xprint("Port {} closed".format(service[1]), 2, 1)
            closed += 1
        s.close()

def syn_scan(flag):
    xprint("Starting SYN Scan", 3)
    opened, closed, filtered = 0, 0, 0
    port_list = most_used_ports()
    for service in port_list:
        target = IP(dst=args.target)/TCP(flags=flag, dport=service[1])
        res = sr1(target, timeout=timeout, verbose=0)
        if res is None:
            filtered += 1
            xprint("Port {} filtered".format(service[1]), 3, 1)
        elif 'ICMP' in res :
            if res['ICMP'].type == 3 and res['ICMP'].code in [0, 1, 2, 9, 10, 13]:
                filtered += 1
                xprint("Port {} filtered".format(service[1]), 3)
            else:
                xprint('autre')
        elif res['TCP'].flags & TCP_flags.SYN:
            opened += 1
            xprint("Port {} {} opened".format(service[1], service[0]), 1)
            seq = res.seq + 1
            target = IP(dst=args.target)/TCP(flags='R', dport=service[1], seq=seq)
            send(target)
        elif res['TCP'].flags & TCP_flags.RST:
            closed += 1
            xprint("Port {} closed".format(service[1]), 2, 1)
        else:
            xprint('autre')
        
    return opened, closed, filtered

def udp_scan():
    xprint("Starting UDP Scan", 3)
    opened, closed, filtered, openedFiltered = 0, 0, 0, 0
    port_list = most_used_ports('udp')
    for service in port_list:
        target = IP(dst=args.target)/UDP(dport=service[1])
        res = sr1(target, timeout=timeout, verbose=0)
        if res is None:
            pass
            openedFiltered += 1
            xprint("Port {} opened|filtered".format(service[1]), 2)
        elif 'ICMP' in res:
            if res['ICMP'].type == 3 and res['ICMP'].code == 3:
                closed += 1
                xprint("Port {} closed".format(service[1]), 2, 1)
                time.sleep(0.9)
            elif res['ICMP'].type == 3 and res['ICMP'].code in [0, 1, 2, 9, 10, 13]:
                filtered += 1
                xprint("Port {} filtered".format(service[1]), 3)
            else:
                xprint('autre')
        elif 'UDP' in res:
            opened += 1
            xprint("Port {} {} opened".format(service[1], service[0]), 1)
        else:
            xprint('autre')
        
    return opened, closed, filtered, openedFiltered

def fin_scan(flag):
    xprint("Starting FIN Scan", 3)
    closed,filtered, openedFiltered = 0, 0, 0
    port_list = most_used_ports()
    for service in port_list:
        target = IP(dst=args.target)/TCP(flags=flag, dport=service[1])
        res = sr1(target, timeout=timeout, verbose=0)
        if res is None:
            openedFiltered += 1
            xprint("Port {} {} opened|filtered".format(service[1], service[0]), 2)
        elif 'TCP' in res:
            if res['TCP'].flags & TCP_flags.RST:
                closed += 1
                xprint("Port {} closed".format(service[1]), 2, 1)
            else:
                xprint('autre')
        elif 'ICMP' in res:
            if res['ICMP'].type == 3  and res['ICMP'].code in [0, 1, 2, 9, 10, 13]:
                filtered += 1
                xprint("Port {} filtered".format(service[1]), 3)
            else:
                xprint('autre')
        else:
            xprint('autre')

    return closed, filtered, openedFiltered

def ack_scan():
    xprint("Starting ACK Scan", 3)
    filtered, unfiltered = 0, 0
    port_list = most_used_ports()
    for service in port_list:
        target = IP(dst=args.target)/TCP(flags='A', dport=service[1])
        res = sr1(target, timeout=timeout, verbose=0)
        if res is None:
            filtered += 1
            xprint("Port {} filtered".format(service[1]), 3)
        elif 'ICMP' in res:
            if res['ICMP'].type == 3  and res['ICMP'].code in [0, 1, 2, 9, 10, 13]:
                filtered += 1
                xprint("Port {} filtered".format(service[1]), 3)
            else:
                xprint('autre')
        elif 'TCP' in res:
            if res['TCP'].flags & TCP_flags.RST:
                unfiltered += 1
                xprint("Port {} unfiltered".format(service[1]), 3, 1)
        else:
            xprint('autre')

    return filtered, unfiltered

def scanflags():
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
    return item[3]

def most_used_ports(proto='tcp'):
    #TODO: add random options
    with open('/usr/share/nmap/nmap-services', 'r') as f:
        D = []
        for line in f:
            if line.startswith('#'):
                continue

            protocol = line.split()[1].split('/')[1]
            if protocol == proto:
                name     = line.split()[0]
                port     = line.split()[1].split('/')[0]
                freq     = line.split()[2]
                D.append([name, int(port), protocol, freq])

        D = sorted(D, key=getFreq, reverse=True)
        if args.all_ports:
            return D
        else:
            return D[:args.top_ports]

def check_ip():
    #TODO: ipv6
    #TODO: gestion of urls
    global timeout
    ip = args.target

    if args.ipv6:
        pass
    else:
        ip = ip.split('.')
        if (ip[0] == '10') or (ip[0] == '172' and ip[1] <= '31' and ip[1] >= '16') or (ip[0] == '192' and ip[1] == '168'):
            timeout = 0.1
        else:
            timeout = 0.5
            

def config():
    arguments()

    if not is_tool('nmap'):
        xprint('Nmap is required to use this script', 2)
        exit()

    colors()
    TCP_flags()
    check_ip()
    conf.verb = 0

    global opened, closed, filtered, openedFiltered, unfiltered
    opened, closed, filtered, openedFiltered, unfiltered = 0, 0, 0, 0, 0

    maxconn=10

    global pool
    pool=threading.BoundedSemaphore(value=maxconn)

   

def main():
    start_time = datetime.now()
    config()

    hostip = socket.gethostbyname(args.target)
    xprint("Scan for {} with IP: {}".format(args.target, hostip), 3)

    if args.sC:
        connect_scan()
    elif args.sU:
        udp_scan()
    elif args.sS:
        syn_scan('S')
    elif args.sF:
        fin_scan('F')
    elif args.sN:
        fin_scan('')
    elif args.sX:
        fin_scan('FPU')
    elif args.sA:
        ack_scan()
    elif args.scanflags:
        flag = scanflags()
        xprint("Starting scan with flag : {}".format(flag), 3)
        syn_scan(flag)
    else:
        xprint("No scan type choosed", 3)
        exit()

    nbscanned = opened + openedFiltered + closed + filtered + unfiltered
    xprint("{} ports scanned".format(nbscanned), 3)
    xprint("{} ports opened".format(opened), 3)
    xprint("{} ports opened|filtered".format(openedFiltered), 3)
    xprint("{} ports closed".format(closed), 3)
    xprint("{} ports filtered".format(filtered), 3)
    xprint("{} ports unfiltered".format(unfiltered), 3)

    xprint("Duration : {}".format(datetime.now() - start_time), 3)


if __name__ == '__main__':
    main()
    #print(most_used_ports('tcp', 10))


#TODO:

#Thread pour lancer plusieurs paquet en même temps
#https://www.ploggingdev.com/2017/01/multiprocessing-and-multithreading-in-python-3/
#https://pymotw.com/3/threading/
#https://www.tutorialspoint.com/python3/python_multithreading.htm
#http://www.tcpcatcher.org/port_scanner.php
#https://gist.github.com/presci/2661576

#TARGET SPECIFICATION:

#HOST DISCOVERY:

#SCAN TECHNIQUES:
# -sY (SCTP INIT scan)
# -sW (TCP Window scan)
# -sM (TCP Maimon scan)
# -sZ (SCTP COOKIE ECHO scan)
# -sI <zombie host>[:<probeport>] (idle scan)
# -sO (IP protocol scan)
# -b <FTP relay host> (FTP bounce scan) 

#PORT SPECIFICATION AND SCAN ORDER:

#SERVICE/VERSION DETECTION:
# -sV: Probe opened ports to determine service/version info

#SCRIPT SCAN:

#OS DETECTION:
# -O: Enable OS detection

#TIMING AND PERFORMANCE:

#FIREWALL/IDS EVASION AND SPOOFING:

#OUTPUT:

#MISC:
# -A: Enable OS detection, version detection, script scanning, and traceroute
