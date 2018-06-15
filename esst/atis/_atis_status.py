# coding=utf-8
"""
ATIS status
"""
import esst.utils.sentry_context


class Status(esst.utils.sentry_context.SentryClassContext):
    """
    ATIS status
    """

    def __init__(self):
        pass

    univers_radio = 'unknown'
    active_atis: dict = {}
