# coding=utf-8
"""
Install a handler to redirect all INFO messages (and higher) to the Discord Channel
"""

import logging

from esst.commands import DISCORD
from esst.core import MAIN_LOGGER

LOGGER = MAIN_LOGGER.getChild(__name__)


class DiscordLoggingHandler(logging.Handler):
    """
    Install a handler to redirect all INFO messages (and higher) to the Discord Channel
    """

    def __init__(self):
        logging.Handler.__init__(self, logging.INFO)

    def emit(self, record: logging.LogRecord):
        """
        Redirects the record to the Discord channel if its level is INFO or higher

        Args:
            record: logging.record to emit
        """
        if isinstance(record.msg, str):
            DISCORD.say(record.msg)


def register_logging_handler():
    """
    Installs the handler to the main logger
    """
    LOGGER.debug('registering Discord logging handler')
    MAIN_LOGGER.addHandler(DiscordLoggingHandler())
