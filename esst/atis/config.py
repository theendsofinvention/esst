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

    DEFAULT_ICAO = elib_config.ConfigValueString(
        'atis', 'default_icao',
        description='When generating the weather from a MIZ file, there is no way to know what ICAO to use.'
                    'By default, ESST will use the "XXXX" ICAO to indicate that. However, that generates '
                    'weather reports fro "unknown airport (XXXX)". To avoid that, you can define a fallback '
                    'value for the ICAO, using a "dummy" ICAO for MIZ generated weathers.',
        default='XXXX'
    )
