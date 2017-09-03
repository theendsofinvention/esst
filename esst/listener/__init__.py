# coding=utf-8
"""
Manages a UDP socket and does two things:

1. Retrieve incoming messages from DCS and update :py:class:`esst.core.status.status`
2. Sends command to the DCS application via the socket
"""

from .listener import DCSListener
