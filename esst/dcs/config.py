# coding=utf-8
"""
Manages DCS config
"""

import elib_config

from esst.sentry.sentry_context import SentryConfigContext


class DCSConfig(SentryConfigContext):
    """
    DCS config values
    """
    DCS_START_LOOP = elib_config.ConfigValueBool(
        'dcs', 'enable',
        description='Enable DCS starting & monitoring',
        default=True
    )

    DCS_CAN_START = elib_config.ConfigValueBool(
        'dcs', 'can_start',
        description='Allow DCS to start',
        default=True
    )

    DCS_PATH = elib_config.ConfigValueString(
        'dcs', 'install_path',
        description='Installation path of DCS.'
    )

    DCS_IDLE_CPU_USAGE = elib_config.ConfigValueInteger(
        'dcs', 'idle_cpu_usage',
        description='Expected maximum CPU usage (in percent) of an idling dcs.exe process.',
        default=5
    )

    DCS_HIGH_CPU_USAGE = elib_config.ConfigValueInteger(
        'dcs', 'high_cpu_usage',
        description='Threshold for high CPU usage alert (in percent). Set to 0 to disable alerts.',
        default=0
    )

    DCS_HIGH_CPU_USAGE_INTERVAL = elib_config.ConfigValueInteger(
        'dcs', 'high_cpu_usage_check_interval',
        description='Interval in seconds between high DCS CPU usage (in seconds).',
        default=5
    )

    DCS_PING_INTERVAL = elib_config.ConfigValueInteger(
        'dcs', 'ping_interval',
        description='Interval, in seconds, between pings to check if DCS is alive & healthy',
        default=30
    )

    DCS_CLOSE_GRACE_PERIOD = elib_config.ConfigValueInteger(
        'dcs', 'close_grace_period',
        description='Amount of time, in seconds, given for DCS to close itself gracefully. '
                    'Passed that delay, the dcs.exe process will be forcefully killed.',
        default=30
    )

    DCS_START_GRACE_PERIOD = elib_config.ConfigValueInteger(
        'dcs', 'start_grace_period',
        description='Amount of time, in seconds, given for DCS to start. Passed that delay, the DCS.exe will be'
                    'considered "hung" and restarted.',
        default=150
    )

    DCS_CPU_AFFINITY = elib_config.ConfigValueList(
        'dcs', 'affinity',
        description='List of (logical) cores (as integers) to set DCS affinity to. '
                    'Examples for logical cores 5 & 7 of a 4 physical cores CPU: [4, 6]',
        default=[],
        element_type=int
    )

    DCS_CPU_PRIORITY = elib_config.ConfigValueString(
        'dcs', 'priority',
        description='CPU priority for the DCS process (valid values are: "idle", "below_normal", '
                    '"normal", "above_normal", "high", and "realtime"',
        default='high'
    )

    DCS_MAX_LOG_AGE = elib_config.ConfigValueInteger(
        'dcs', 'max_log_age',
        description='Set a maximum age (in days) for DCS logs to be kept. Set to 0 to disable.',
        default=0
    )

    DCS_AUTO_MISSION_GH_OWNER = elib_config.ConfigValueString(
        'dcs', 'auto_mission_gh_owner',
        description='Owner of the Github repository to grab the latest MIZ file from',
        default=''
    )

    DCS_AUTO_MISSION_GH_REPO = elib_config.ConfigValueString(
        'dcs', 'auto_mission_gh_repo',
        description='Github repository to grab the latest MIZ file from',
        default=''
    )

    DCS_AUTO_MISSION_ENABLE = elib_config.ConfigValueBool(
        'dcs', 'enable_auto_mission',
        description='Enable pulling latest version of a mission from Github',
        default=False
    )

    DCS_INSTALL_HOOKS = elib_config.ConfigValueBool(
        'dcs', 'install_hooks',
        description='Install DCS API hook LUA script at startup',
        default=True
    )

    DCS_INSTALL_DEDICATED_CONFIG = elib_config.ConfigValueBool(
        'dcs', 'install_dedicated_config',
        description='Install dedicated.lua config script at startup',
        default=True
    )
