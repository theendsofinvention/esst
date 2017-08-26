# coding=utf-8
"""
Manages ESST configuration
"""

import inspect
import os

import everett
import everett.manager


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

    def get_context(self) -> dict:
        return {member: value
                for member, value in inspect.getmembers(self, lambda a: not (inspect.ismethod(a)))
                if not member.startswith('_')
                }

    def __init__(self, version):
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
                        'SENTRY_DSN': '',
                        'DCS_IDLE_CPU_USAGE': 5,
                        'DCS_HIGH_CPU_USAGE': 80,
                        'DCS_HIGH_CPU_USAGE_INTERVAL': 5,
                        'DISCORD_BOT_NAME': 'ESST',
                        'DISCORD_MOTD': 'Hello!\n'
                                        'This is ESST v{version}\n'
                                        'Type "!help" for a list of available commands'.format(version=version),
                        'AUTO_MISSION_GITHUB_TOKEN': '',
                        'AUTO_MISSION_GITHUB_OWNER': '',
                        'AUTO_MISSION_GITHUB_REPO': '',
                        'DCS_SERVER_STARTUP_TIME': 120,
                        'DCS_PING_INTERVAL': 30,
                        'START_SERVER': 'true',
                        'START_LISTENER': 'true',
                        'START_BOT': 'true',
                        'DCS_CAN_START': 'true'
                    }
                ),
            ]
        )

        self.debug = self._config('DEBUG', default='false', parser=everett.manager.parse_bool)
        self.saved_games_dir = self._config('SAVED_GAMES_DIR', parser=str)
        self.sentry_dsn = self._config('SENTRY_DSN', parser=str)
        self.start_server = self._config('START_SERVER', parser=bool)
        self.start_bot = self._config('START_BOT', parser=bool)
        self.start_listener = self._config('START_LISTENER', parser=bool)
        self.dcs_can_start = self._config('DCS_CAN_START', parser=bool)

        self.dcs_path = self._config('PATH', parser=parse_dcs_path, namespace='DCS')
        self.dcs_idle_cpu_usage = self._config('IDLE_CPU_USAGE', parser=int, namespace='DCS')
        self.dcs_high_cpu_usage = self._config('HIGH_CPU_USAGE', parser=int, namespace='DCS')
        self.dcs_high_cpu_usage_interval = self._config('HIGH_CPU_USAGE_INTERVAL', parser=int, namespace='DCS')
        self.dcs_server_password = self._config('SERVER_PASSWORD', parser=str, namespace='DCS')
        self.dcs_ping_interval = self._config('PING_INTERVAL', parser=int, namespace='DCS')

        self.dcs_server_name = self._config('NAME', parser=str, namespace='DCS_SERVER')
        self.dcs_server_max_players = self._config('MAX_PLAYERS', parser=int, namespace='DCS_SERVER')
        self.dcs_server_startup_time = self._config('STARTUP_TIME', parser=int, namespace='DCS_SERVER')
        self.dcs_server_event_role = self._config(
            'EVENT_ROLE', parser=str, namespace='DCS_SERVER', default='true'
        )
        self.dcs_server_require_pure_clients = self._config(
            'require_pure_clients', parser=str, namespace='DCS_SERVER', default='false'
        )
        self.dcs_server_allow_ownship_export = self._config(
            'allow_ownship_export', parser=str, namespace='DCS_SERVER', default='true'
        )
        self.dcs_server_allow_object_export = self._config(
            'allow_object_export', parser=str, namespace='DCS_SERVER', default='true'
        )

        self.discord_bot_name = self._config('BOT_NAME', parser=str, namespace='DISCORD')
        self.discord_channel = self._config('CHANNEL', parser=str.lower, namespace='DISCORD')
        self.discord_token = self._config('TOKEN', parser=str, namespace='DISCORD')
        self.discord_motd = self._config('MOTD', parser=str, namespace='DISCORD')

        self.auto_mission_github_token = self._config('GITHUB_TOKEN', parser=str, namespace='AUTO_MISSION')
        self.auto_mission_github_owner = self._config('GITHUB_OWNER', parser=str, namespace='AUTO_MISSION')
        self.auto_mission_github_repo = self._config('GITHUB_REPO', parser=str, namespace='AUTO_MISSION')
