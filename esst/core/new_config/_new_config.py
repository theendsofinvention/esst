# coding=utf-8
"""
Manages config params for auto mission
"""
import inspect
import sys

from elib.config import BaseConfig, ConfigProp

from ._atis import ATISConfig
from ._auto_mission import AutoMissionConfig
from ._dcs import DCSConfig
from ._dcs_server import DCSServerConfig
from ._discord_bot import DiscordConfig
from ._remove_old_files import RemoveOldFile
from ._univers_radio import URConfig


# pylint: disable=too-many-ancestors
class ESSTConfig(BaseConfig,
                 DCSConfig,
                 DCSServerConfig,
                 AutoMissionConfig,
                 RemoveOldFile,
                 DiscordConfig,
                 URConfig,
                 ATISConfig):
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
        if hasattr(sys, '_called_from_test'):
            package_name: str = 'esst_test'
        else:
            package_name: str = 'esst'
        BaseConfig.__init__(self, package_name)

    debug = ConfigProp(bool, default='false')
    restart = ConfigProp(str, default='')
    saved_games_dir = ConfigProp(str, default='')
    # noinspection SpellCheckingInspection
    sentry_dsn = ConfigProp(
        str,
        default='https://85518bcfd75a400eaf3821830ec1c4b2:a622d4e7a4ab4ec9ade873ad96b8d4aa@sentry.io/206995'
    )
    start_server_loop = ConfigProp(bool, default='true')
    start_dcs_loop = ConfigProp(bool, default='true')
    start_discord_loop = ConfigProp(bool, default='true')
    start_listener_loop = ConfigProp(bool, default='true')
