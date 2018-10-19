# coding=utf-8
"""
Manages server config
"""

import elib_config

from esst.sentry.sentry_context import SentryConfigContext


class ServerConfig(SentryConfigContext):
    """
    Manages configuration for the server monitor
    """
    SERVER_START_LOOP = elib_config.ConfigValueBool(
        'server', 'enable',
        description='Enable server monitoring',
        default=True
    )
