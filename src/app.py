"""
    A module docstring.
"""

# TODO: faire de ce fichier un namespace

from typing import List, Iterator

# results: Dict[str, Any] = {}


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
    # TODO: maybe use re instead of split
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
