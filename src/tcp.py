"""
    A module docstring.
"""


class TCP:
    """docstring for TCP"""
    # TODO: make if res['TCP'].flags & TCP.SYN:  simpler
    # for exemple: if has(TCP.SYN, res['TCP'.flags]):

    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80

    def __init__(self) -> None:
        pass

    @staticmethod
    def scanflags(flags: str) -> str:
        """Parse a string and return the TCP flag in this string."""
        flag = ''
        if 'FIN' in flags:
            flag += 'F'
        if 'SYN' in flags:
            flag += 'S'
        if 'RST' in flags:
            flag += 'R'
        if 'PSH' in flags:
            flag += 'P'
        if 'ACK' in flags:
            flag += 'A'
        if 'URG' in flags:
            flag += 'U'
        if 'ECE' in flags:
            flag += 'E'
        if 'CWR' in flags:
            flag += 'C'
        return flag
