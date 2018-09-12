# coding=utf-8
"""
Commands for the socket listener
"""

from esst.core import CTX, MAIN_LOGGER

LOGGER = MAIN_LOGGER.getChild(__name__)


class LISTENER:
    """
    Commands for the socket listener
    """

    @staticmethod
    def monitor_server_startup_start():
        """Starts monitoring DCS startup"""
        LOGGER.debug('monitor server startup: start')
        CTX.listener_monitor_server_startup = True

    @staticmethod
    def monitor_server_startup_stop():
        """Stops monitoring server startup"""
        LOGGER.debug('monitor server startup: stop')
        CTX.listener_monitor_server_startup = False

    @staticmethod
    def exit_dcs():
        """Sends a socket signal to stop DCS"""
        LOGGER.debug('sending socket message to close DCS')
        CTX.listener_cmd_queue.put('exit dcs')
