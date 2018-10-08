# coding=utf-8
"""
Etcher's Server Startup Tool
"""
# pylint: disable=wrong-import-position

from pkg_resources import DistributionNotFound, get_distribution

try:
    __version__ = get_distribution('esst').version
except DistributionNotFound:  # pragma: no cover
    # package is not installed
    __version__ = 'not installed'

from ._esst_logging import LOGGER, LOGGING_CONSOLE_HANDLER

from esst.atis.config import ATISConfig
from esst.dcs.config import DCSConfig
from esst.discord_bot.config import DiscordBotConfig
from esst.listener.config import ListenerConfig
from esst.server.config import ServerConfig
from esst.dcs.config_server import DCSServerConfig
from esst.config import ESSTConfig
from esst.fs_paths import FS
