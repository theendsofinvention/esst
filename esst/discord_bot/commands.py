# coding=utf-8
"""
Manages Discord commands
"""

from esst import LOGGER
from esst.core import CTX


class DISCORD:
    """
    Manages Discord commands
    """

    @staticmethod
    def say(message):
        """
        Sends a message on the active channel

        Args:
            message: string to send

        """
        CTX.discord_msg_queue.put(message[:1].upper() + message[1:])

    @staticmethod
    def send_file(file_path: str):
        """
        Sends a file to the active channel

        Args:
            file_path: path to the file to send

        """
        LOGGER.debug('sending file to Discord: %s', file_path)
        CTX.discord_file_queue.put(file_path)

    @staticmethod
    def can_start():
        """DCS can start"""
        if not CTX.discord_can_start:
            LOGGER.debug('Discord can start')
        CTX.discord_can_start = True

    @staticmethod
    def cannot_start():
        """DCS cannot start"""
        if CTX.discord_can_start:
            LOGGER.debug('Discord can NOT start')
        CTX.discord_can_start = False
