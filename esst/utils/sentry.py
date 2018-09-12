# coding=utf-8
"""
Connection with sentry.io
"""

import logging
import sys

import certifi
import raven
import raven.breadcrumbs
import raven.conf
import raven.handlers.logging

from esst import __version__
from esst.core import MAIN_LOGGER

LOGGER = MAIN_LOGGER.getChild(__name__)


class Sentry(raven.Client):
    """
    Connection with sentry.io
    """

    def __init__(self, dsn):
        LOGGER.info('initializing Sentry')
        self.registered_contexts = {}
        raven.Client.__init__(
            self,
            f'{dsn}?ca_certs={certifi.where()}',
            release=__version__,
        )
        if self.is_enabled():
            LOGGER.info('Sentry is ready')

    def set_context(self):
        """
        Sets Sentry context

        """
        self.tags_context(
            dict(
                platform=sys.platform,
                version=__version__,
            )
        )
        try:
            self.tags_context(dict(windows_version=sys.getwindowsversion()))
        except AttributeError:
            pass

    def register_context(self, context_name: str, context_provider):
        """Registers a context to be read when a crash occurs; obj must implement get_context()"""
        LOGGER.debug(
            'registering context with Sentry: {}'.format(context_name))
        self.registered_contexts[context_name] = context_provider

    @staticmethod
    def add_crumb(message, category, level):
        """
        Manually add a crumb to the logger

        Args:
            message: message str
            category: category
            level: logging level

        """
        raven.breadcrumbs.record(
            message=message, category=category, level=level)

    def captureMessage(self, message, **kwargs):  # noqa: N802
        """
        Manually add a message

        Args:
            message: message content
            **kwargs: meh

        """
        self.set_context()
        if kwargs.get('data') is None:
            kwargs['data'] = {}
        if kwargs['data'].get('level') is None:
            kwargs['data']['level'] = logging.DEBUG
        for context_name, context_provider in self.registered_contexts.items():
            self.extra_context({context_name: context_provider.get_context()})
        super(Sentry, self).captureMessage(message, **kwargs)

    def captureException(self, exc_info=None, **kwargs):
        """Captures an exception"""
        self.set_context()

        LOGGER.debug('capturing exception')
        for k, context_provider in self.registered_contexts.items():
            self.extra_context({k: context_provider.get_context()})
        super(Sentry, self).captureException(exc_info, **kwargs)


# noinspection PyUnusedLocal
def filter_breadcrumbs(_logger, level, msg, *args, **kwargs):  # pylint: disable=unused-argument
    """
    Intercepts logging messages

    Args:
        _logger: originating logger
        level: record level
        msg: record message
        *args: logging args
        **kwargs: logging kwargs

    """
    skip_lvl = []
    skip_msg = []

    if level in skip_lvl or msg in skip_msg:
        return False

    if _logger == 'requests':
        return False
    return True


raven.breadcrumbs.register_special_log_handler('ESST', filter_breadcrumbs)
