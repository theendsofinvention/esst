# coding=utf-8
"""
Manages config params for ATIS
"""

import elib_config

from esst.sentry.sentry_context import SentryConfigContext


class ATISConfig(SentryConfigContext):
    """
    Configuration for the ATIS package
    """

    ATIS_CREATE = elib_config.ConfigValueBool(
        'atis', 'create',
        description='create ATIS mp3 files when starting ESST',
        default=True,
    )

    UR_PATH = elib_config.ConfigValueString(
        'atis', 'ur_path',
        description='Path to UR config folder (usually found in Saved Games)',
        default=''
    )
