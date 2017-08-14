# coding=utf-8
"""
Manages ESST configuration
"""

import os

import everett
import everett.manager

from esst.core.version import __version__


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


def parse_saved_games_dir(val):
    """
    Checks that a value passed for SAVED_GAMES_DIR is valid

    Args:
        val: value

    Raises:
        ValueError: if value is incorrect

    Returns: value is value is correct
    """
    if not os.path.exists(val):
        raise ValueError(f'SAVED_GAMES_DIR does not exist: {val}')

    to_check = [
        'Scripts',
        'Config',
    ]
    for check in to_check:
        if not os.path.exists(os.path.join(val, check)):
            raise ValueError(f'SAVED_GAMES_DIR should contain a directory named "{check}"')

    if not os.path.basename(val) == 'dcs.exe':
        raise ValueError(f'SAVED_GAMES_DIR should point to "dcs.exe"')

    return os.path.normpath(val)


class Config:  # pylint: disable=too-many-instance-attributes,too-few-public-methods
    """
    Singleton configuration class for ESST.
    """

    def __init__(self):
        self._config = everett.manager.ConfigManager(
            [

                everett.manager.ConfigEnvFileEnv('.env'),
                everett.manager.ConfigOSEnv(),
                everett.manager.ConfigIniEnv(
                    [
                        os.environ.get('ESST_INI'),
                        os.path.join(os.path.expanduser('~'), 'esst.ini'),
                        './esst.ini',
                    ]
                ),
                everett.manager.ConfigDictEnv(
                    {
                        'DEBUG': 'false',
                        'DCS_IDLE_CPU_USAGE': 5,
                        'DCS_HIGH_CPU_USAGE': 80,
                        'DISCORD_BOT_NAME': 'ESST',
                        'DISCORD_MOTD': 'Hello!\n'
                                        'This is ESST v{version}\n'
                                        'Type "!help" for a list of available commands'.format(version=__version__),
                        'AUTO_MISSION_GITHUB_TOKEN': '',
                        'AUTO_MISSION_GITHUB_OWNER': '',
                        'AUTO_MISSION_GITHUB_REPO': '',
                        'DCS_SERVER_STARTUP_TIME': 120,
                        'DCS_PING_INTERVAL': 30,
                    }
                ),
            ]
        )

        self.debug = self._config('DEBUG', default='false', parser=everett.manager.parse_bool)
        self.saved_games_dir = self._config('SAVED_GAMES_DIR', parser=str)

        self.dcs_path = self._config('PATH', parser=parse_dcs_path, namespace='DCS')
        self.dcs_idle_cpu_usage = self._config('IDLE_CPU_USAGE', parser=int, namespace='DCS')
        self.dcs_high_cpu_usage = self._config('HIGH_CPU_USAGE', parser=int, namespace='DCS')
        self.dcs_server_password = self._config('SERVER_PASSWORD', parser=str, namespace='DCS')
        self.dcs_server_name = self._config('SERVER_NAME', parser=str, namespace='DCS')
        self.dcs_server_max_players = self._config('SERVER_MAX_PLAYERS', parser=int, namespace='DCS')
        self.dcs_server_startup_time = self._config('SERVER_STARTUP_TIME', parser=int, namespace='DCS')
        self.dcs_ping_interval = self._config('PING_INTERVAL', parser=int, namespace='DCS')

        self.discord_bot_name = self._config('BOT_NAME', parser=str, namespace='DISCORD')
        self.discord_channel = self._config('CHANNEL', parser=str.lower, namespace='DISCORD')
        self.discord_token = self._config('TOKEN', parser=str, namespace='DISCORD')
        self.discord_motd = self._config('MOTD', parser=str, namespace='DISCORD')

        self.auto_mission_github_token = self._config('GITHUB_TOKEN', parser=str, namespace='AUTO_MISSION')
        self.auto_mission_github_owner = self._config('GITHUB_OWNER', parser=str, namespace='AUTO_MISSION')
        self.auto_mission_github_repo = self._config('GITHUB_REPO', parser=str, namespace='AUTO_MISSION')


try:
    CFG = Config()
except everett.InvalidValueError as exception:
    KEY = exception.key
    if exception.namespace:
        KEY = f'{exception.namespace}_{KEY}'
    print(f'Invalid value for key: {KEY}')
    exit(1)
except everett.ConfigurationMissingError as exception:
    KEY = exception.key
    if exception.namespace:
        KEY = f'{exception.namespace}_{KEY}'
    print(f'Missing configuration for key: {KEY}')
    exit(1)

__all__ = ['CFG']
