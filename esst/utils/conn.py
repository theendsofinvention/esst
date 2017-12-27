# coding=utf-8
"""
Checks WAN connection
"""

import ipgetter

from esst import core

LOGGER = core.MAIN_LOGGER.getChild(__name__)


def external_ip():
    """
    Returns: external IP of this machine
    """
    return ipgetter.IPgetter().get_externalip()
