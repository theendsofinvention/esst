# coding=utf-8
"""
Install a handler to redirect all INFO messages (and higher) to the Discord Channel
"""

import logging

from esst import LOGGER
from esst.commands import DISCORD

_SKIP_LOGGERS = (
    'asyncio',
    'discord.http',
    'discord.gateway',
)


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
        if record.name in _SKIP_LOGGERS:
            return

        message = self.format(record)
        DISCORD.say(str(message))


def register_logging_handler():
    """
    Installs the handler to the main logger
    """
    LOGGER.debug('registering Discord logging handler')
    LOGGER.addHandler(DiscordLoggingHandler())
