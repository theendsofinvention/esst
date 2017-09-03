# coding=utf-8
# pylint: disable=bad-whitespace,missing-docstring
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
        CTX.sentry.captureMessage(ctx + '_' + str(uuid.uuid4()), data={'extra': {'text': ' '.join(msg)}})
        DISCORD.say('Thank you !')


@arg('issue', nargs='+', metavar='ISSUE')
def issue(issue_):
    """
    Load a mission, allowing to set the weather or the time (protected)
    """
    _send(issue_, 'ISSUE')


@arg('suggestion', nargs='+', metavar='SUGGESTION')
def suggestion(suggestion_):
    """
    Load a mission, allowing to set the weather or the time (protected)
    """
    _send(suggestion_, 'SUGGESTION')


NAMESPACE = '!report'
TITLE = 'Report issues, request features, ...'
