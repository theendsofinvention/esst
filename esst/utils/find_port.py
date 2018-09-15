# coding=utf-8
"""
Randomize socket ports at startup
"""

import random
import socket
from contextlib import contextmanager

from esst.core import CTX

# TODO: this needs to be a config value later on when I switch to TOML & elib_config
_RANGE = range(50000, 60000)


@contextmanager
def _socket():
    _sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    yield _sock
    _sock.close()


def _port_available(port_number: int) -> bool:
    with _socket() as sock:
        result = sock.connect_ex(('localhost', port_number))
    return result == 0


def _find_available_port() -> int:
    """
    Finds an unbound port on localhost

    :return: available port number
    :rtype: int
    """
    barrier = 0
    limit = 100
    while True:
        port_number = random.choice(_RANGE)  # nosec
        if _port_available(port_number):
            return port_number
        barrier += 1
        if barrier > limit:
            raise RuntimeError(f'unable to find any unbound local port after {limit} tries')


def assign_ports() -> None:
    """
    Assigns random ports for the listener sockets
    """
    CTX.listener_server_port = _find_available_port()
    CTX.listener_cmd_port = _find_available_port()
