# coding=utf-8
# pylint: disable=missing-docstring
"""
Manages Discord commands
"""

from esst.core import CTX, MAIN_LOGGER

LOGGER = MAIN_LOGGER.getChild(__name__)


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
    def send(file_path):
        """
        Sends a file to the active channel

        Args:
            file_path: path to the file to send

        """
        CTX.discord_file_queue.put(file_path)

    @staticmethod
    def can_start():
        if not CTX.discord_can_start:
            LOGGER.debug('Discord can start')
        CTX.discord_can_start = True

    @staticmethod
    def cannot_start():
        if CTX.discord_can_start:
            LOGGER.debug('Discord can NOT start')
        CTX.discord_can_start = False
