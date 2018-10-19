# coding=utf-8
"""
Meh
"""
import uuid

from esst import commands, core, utils


def _send(msg, ctx):
    if msg and core.CTX.sentry:
        core.CTX.sentry.captureMessage(
            ctx + '_' + str(uuid.uuid4()), data={'extra': {'text': ' '.join(msg)}})
        commands.DISCORD.say('Thank you !')


@utils.arg('message', nargs='+', metavar='ISSUE')
def issue(message):
    """
    Send feedback about an issue with ESST
    """
    _send(message, 'ISSUE')


@utils.arg('message', nargs='+', metavar='SUGGESTION')
def suggestion(message):
    """
    Suggest a new feature
    """
    _send(message, 'SUGGESTION')


NAMESPACE = '!report'
TITLE = 'Report issues, request features, ...'
