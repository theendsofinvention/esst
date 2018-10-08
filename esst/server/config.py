# coding=utf-8
"""
Manages server config
"""

from elib_config import ConfigValueBool

from esst.sentry.sentry_context import SentryConfigContext


class ServerConfig(SentryConfigContext):
    """
    Manages configuration for the server monitor
    """
    SERVER_START_LOOP = ConfigValueBool(
        'server', 'enable',
        description='Enable server monitoring',
        default=True
    )
