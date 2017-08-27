# coding=utf-8
"""
Manages Discord commands
"""

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
        CTX.discord_msg_queue.put(message)

    @staticmethod
    def send(file_path):
        """
        Sends a file to the active channel

        Args:
            file_path: path to the file to send

        """
        CTX.discord_file_queue.put(file_path)
