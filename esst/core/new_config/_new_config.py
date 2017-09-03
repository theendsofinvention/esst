# coding=utf-8

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
    def __init__(self):
        BaseConfig.__init__(self, 'esst')
        pass

    @ConfigProp(bool)
    def debug(self):
        pass

    @ConfigProp(str)
    def saved_games_dir(self):
        pass

    @ConfigProp(str, '')
    def sentry_dsn(self):
        pass

    @ConfigProp(bool, True)
    def start_server_loop(self):
        pass

    @ConfigProp(bool, True)
    def start_dcs_loop(self):
        pass

    @ConfigProp(bool, True)
    def start_discord_loop(self):
        pass

    @ConfigProp(bool, True)
    def start_listener_loop(self):
        pass

    @ConfigProp(bool, True)
    def dcs_can_start(self):
        pass
