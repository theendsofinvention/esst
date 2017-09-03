# coding=utf-8
"""
Manages config params for auto mission
"""

import inspect
import os

from elib.config import BaseConfig, ConfigProp

from ._auto_mission import AutoMissionConfig
from ._dcs import DCSConfig
from ._dcs_server import DCSServerConfig
from ._discord_bot import DiscordConfig


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


class ESSTConfig(BaseConfig,
                 DCSConfig,
                 DCSServerConfig,
                 AutoMissionConfig,
                 DiscordConfig):
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

    @ConfigProp(bool)
    def debug(self):
        """
        Outputs debug messages on the console
        """
        pass

    @ConfigProp(str)
    def saved_games_dir(self):
        """
        Path to "Saved Games" folder
        """
        pass

    @ConfigProp(str, '')
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
