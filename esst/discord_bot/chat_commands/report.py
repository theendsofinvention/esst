# coding=utf-8
# pylint: disable=bad-whitespace,missing-docstring
"""
Meh
"""
import uuid
from esst.core import MAIN_LOGGER, CTX
from esst.commands import DISCORD

from .arg import arg

LOGGER = MAIN_LOGGER.getChild(__name__)


def _send(msg, ctx):
    if msg and CTX.sentry:
        CTX.sentry.captureMessage(ctx + '_' + str(uuid.uuid4()), data={'extra': {'text': ' '.join(msg)}})
        DISCORD.say('Thank you !')


@arg('issue', nargs='+', metavar='ISSUE')
def issue(issue):
    """
    Load a mission, allowing to set the weather or the time (protected)
    """
    _send(issue, 'ISSUE')


@arg('suggestion', nargs='+', metavar='SUGGESTION')
def suggestion(suggestion):
    """
    Load a mission, allowing to set the weather or the time (protected)
    """
    _send(suggestion, 'SUGGESTION')


NAMESPACE = '!report'
TITLE = 'Report issues, request features, ...'
