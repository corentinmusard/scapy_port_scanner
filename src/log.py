"""
    Log functions
"""

import sys

SUCCESS = 1
FAILURE = 2
INFORMATION = 3


def log(content: str = '', design: int = INFORMATION,
        verbosity: int = 0, current_verbosity: int = 0) -> None:
    """Print strings to stdout."""
    start = ''
    if design == 1:
        start = Colors.success
    elif design == 2:
        start = Colors.failure
    elif design == 3:
        start = Colors.information

    if current_verbosity >= verbosity:
        sys.stdout.write(start + content + '\n')
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
