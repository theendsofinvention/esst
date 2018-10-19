# coding=utf-8
"""
Main ESST config module
"""

import sys

import elib_config

from esst import LOGGER, __version__
from esst.sentry.sentry import SENTRY
from esst.sentry.sentry_context import SentryConfigContext


class ESSTConfig(SentryConfigContext):
    """
    Main ESST config values
    """
    DEBUG = elib_config.ConfigValueBool(
        'debug',
        description='outputs debug messages to console',
        default=False
    )

    SAVED_GAMES_DIR = elib_config.ConfigValueString(
        'saved_games_folder',
        description='Path to the "Saved Games" folder (no trailing "DCS")',
        default=''
    )


def init() -> None:
    """
    Makes sure the configuration is valid before starting ESST

    :raise: SystemExit
    """
    # Setup elib_config
    elib_config.ELIBConfig.setup(
        app_version=__version__,
        app_name='ESST',
        config_file_path='esst.toml',
        config_sep_str='__',
    )

    # Write example config file
    elib_config.write_example_config('esst.toml.example')

    # Validate config
    try:
        elib_config.validate_config()
    except elib_config.ConfigMissingValueError as error:
        LOGGER.error('missing mandatory config value: %s', error.value_name)
        LOGGER.error('please read "esst.toml.example" for instructions on how to setup the configuration for ESST')
        sys.exit(1)

    for config in SentryConfigContext.__subclasses__():
        SENTRY.register_context(context_name=config.__name__, context_provider=config)
