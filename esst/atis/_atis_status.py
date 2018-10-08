# coding=utf-8
"""
ATIS status
"""
from esst.sentry.sentry_context import SentryClassContext


class Status(SentryClassContext):
    """
    ATIS status
    """

    def __init__(self):
        pass

    univers_radio = 'unknown'
    active_atis: dict = {}
