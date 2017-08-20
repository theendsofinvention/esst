# coding=utf-8
"""
Install a handler to redirect all INFO messages (and higher) to the Discord Channel
"""

import logging

from esst.core.logger import MAIN_LOGGER
from esst.core.context import Context


LOGGER = MAIN_LOGGER.getChild(__name__)


class DiscordLoggingHandler(logging.Handler):
    """
    Install a handler to redirect all INFO messages (and higher) to the Discord Channel
    """

    def __init__(self, ctx: Context):
        logging.Handler.__init__(self, logging.INFO)
        self.ctx = ctx

    def emit(self, record: logging.LogRecord):
        """
        Redirects the record to the Discord channel if its level is INFO or higher

        Args:
            record: logging.record to emit
        """
        self.ctx.discord_msg_queue.put(record.msg[:1].upper() + record.msg[1:])


def register_logging_handler(ctx):
    """
    Installs the handler to the main logger
    """
    LOGGER.debug('registering Discord logging handler')
    MAIN_LOGGER.addHandler(DiscordLoggingHandler(ctx))
