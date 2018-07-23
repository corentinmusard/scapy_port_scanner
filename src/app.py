"""
    A module docstring.
"""

# TODO: faire de ce fichier un namespace


from typing import List, Any, Dict, Iterator
import sys
import argparse
from datetime import datetime

from .tcp import TCP
from .ip import IP

results: Dict[str, Any] = {}
timeout: float = 1.0
args: argparse.Namespace = argparse.Namespace()
ipv6: bool = False
flag: str = ''

SUCCESS = 1
FAILURE = 2
INFORMATION = 3


def xprint(content: str = '', design: int = INFORMATION, verbosity: int = 0) -> None:
    """Print strings to stdout."""
    begin = ''
    if design == 1:
        begin = Colors.success
    elif design == 2:
        begin = Colors.failure
    elif design == 3:
        begin = Colors.information

    if args.verbosity >= verbosity:
        sys.stdout.write(begin + content + '\n')
        sys.stdout.flush()


class Colors:
    """Constants for coloring output."""

    red = '\033[1;31m'
    green = '\033[1;32m'
    blue = '\033[1;34m'
    end = '\033[0m'

    success = green + '[+]' + end + ' '
    failure = red + '[-]' + end + ' '
    information = blue + '[*]' + end + ' '

    def __init__(self) -> None:
        pass


def is_tool(name: str) -> bool:
    """Check whether `name` is on PATH and marked as executable."""
    from shutil import which
    return which(name) is not None


def get_freq(item: List) -> str:
    """Return the open's frequence of the desired service."""
    return item[3]


def most_used_ports(proto: str = 'tcp', nbports: int = None) -> Iterator[List]:
    """Parse the nmap's service file and Return the most used ports."""
    # TODO: add random options
    # TODO: remove the nmap's dependences
    # TODO: make the function os agnostic
    # TODO: maybe be use re instead of split
    with open('/usr/share/nmap/nmap-services', 'r') as file:
        service_list = []
        for line in file:
            if line.startswith('#'):
                continue

            protocol = line.split()[1].split('/')[1]

            if protocol == proto:
                name = line.split()[0]
                port = line.split()[1].split('/')[0]
                freq = line.split()[2]
                service_list.append([name, int(port), protocol, freq])

        service_list = sorted(service_list, key=get_freq, reverse=True)
        if nbports is None:
            return (service for service in service_list)

        return (service for service in service_list[:nbports])


def end(start_time: datetime = None) -> None:
    """"""

    for key in results:
        if key is not None:
            xprint(f'{results[key]} ports {key}', INFORMATION)

    if start_time is not None:
        xprint(f'Duration : {datetime.now() - start_time}', INFORMATION)
