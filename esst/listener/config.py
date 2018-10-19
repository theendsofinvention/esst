# coding=utf-8
"""
Manages listener config
"""

import elib_config

from esst.sentry.sentry_context import SentryConfigContext


class ListenerConfig(SentryConfigContext):
    """
    Manages configuration for the socket daemon
    """

    LISTENER_START_LOOP = elib_config.ConfigValueBool(
        'listener', 'enable',
        description='Enable the socket daemon used to communicate with DCS',
        default=True
    )
