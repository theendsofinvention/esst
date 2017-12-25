# coding=utf-8
"""
Meh
"""
import uuid

from esst.commands import DISCORD
from esst.core import CTX, MAIN_LOGGER

from .arg import arg

LOGGER = MAIN_LOGGER.getChild(__name__)


def _send(msg, ctx):
    if msg and CTX.sentry:
        CTX.sentry.captureMessage(
            ctx + '_' + str(uuid.uuid4()), data={'extra': {'text': ' '.join(msg)}})
        DISCORD.say('Thank you !')


@arg('message', nargs='+', metavar='ISSUE')
def issue(message):
    """
    Send feedback about an issue with ESST
    """
    _send(message, 'ISSUE')


@arg('message', nargs='+', metavar='SUGGESTION')
def suggestion(message):
    """
    Suggest a new feature
    """
    _send(message, 'SUGGESTION')


NAMESPACE = '!report'
TITLE = 'Report issues, request features, ...'
