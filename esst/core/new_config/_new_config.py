# coding=utf-8
"""
Manages config params for auto mission
"""

import inspect
import os

import everett
from elib.config import BaseConfig, ConfigProp

from ._auto_mission import AutoMissionConfig
from ._dcs import DCSConfig
from ._dcs_server import DCSServerConfig
from ._discord_bot import DiscordConfig
from ._remove_old_files import RemoveOldFile
from ._univers_radio import URConfig
from ._validate_config import validate_config


def parse_dcs_path(val: str) -> str:
    """
    Checks that a value passed for DCS_PATH is valid

    Args:
        val: value

    Raises:
        ValueError: if value is incorrect

    Returns: value is value is correct
    """
    if not os.path.exists(val):
        raise ValueError(f'DCS_PATH does not exist: {val}')

    if not os.path.basename(val) == 'dcs.exe':
        raise ValueError(f'DCS_PATH should point to "dcs.exe"')

    return os.path.normpath(val)

# pylint: disable=too-many-ancestors


class ESSTConfig(BaseConfig,
                 DCSConfig,
                 DCSServerConfig,
                 AutoMissionConfig,
                 RemoveOldFile,
                 DiscordConfig,
                 URConfig):
    """
    Manages config params for auto mission
    """

    def get_context(self) -> dict:
        """

        Returns: dict context for Sentry

        """
        return {
            member: value
            for member, value in inspect.getmembers(self, lambda a: not inspect.ismethod(a))
            if not member.startswith('_')
        }

    def __init__(self):
        BaseConfig.__init__(self, 'esst')

    @ConfigProp(bool, default=False)
    def debug(self):
        """
        Outputs debug messages on the console
        """
        pass

    @ConfigProp(str, default='')
    def saved_games_dir(self):
        """
        Path to "Saved Games" folder
        """
        pass

    @ConfigProp(str, 'https://85518bcfd75a400eaf3821830ec1c4b2:a622d4e7a4ab4ec9ade873ad96b8d4aa@sentry.io/206995')
    def sentry_dsn(self):
        """
        Optional Sentry DSN to send crash reports
        """
        pass

    @ConfigProp(bool, True)
    def start_server_loop(self):
        """
        Starts the server loop ("server" is the machine on which DCS is running)
        """
        pass

    @ConfigProp(bool, True)
    def start_dcs_loop(self):
        """
        Starts the DCS loop
        """
        pass

    @ConfigProp(bool, True)
    def start_discord_loop(self):
        """
        Starts the Discord bot loop
        """
        pass

    @ConfigProp(bool, True)
    def start_listener_loop(self):
        """
        Starts the listening socket loop
        """
        pass

    @ConfigProp(bool, True)
    def dcs_can_start(self):
        """
        Allow DCS application to actually start
        """
        pass


def setup_config():
    """
    Set up the config object

    Returns: instance of ESSTConfig

    """
    try:
        config = ESSTConfig()
        validate_config(config)
    except everett.InvalidValueError as exception:
        key = exception.key
        if exception.namespace:
            key = f'{exception.namespace}_{key}'
        print(f'Invalid config value: {key}')
        exit(1)
    except everett.ConfigurationMissingError as exception:
        key = exception.key
        if exception.namespace:
            key = f'{exception.namespace}_{key}'
        print(f'Missing configuration value: {key}')
        exit(1)
    else:
        return config
