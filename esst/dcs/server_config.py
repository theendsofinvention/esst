# coding=utf-8
"""
Config module for the DCS server configuration
"""

import elib_config

DCS_SERVER_NAME = elib_config.ConfigValueString(
    'dcs_server', 'server_name',
    description='DCS Server name as it will appear in the multiplayer lobby.'
)

DCS_SERVER_MAX_PLAYERS = elib_config.ConfigValueInteger(
    'dcs_server', 'max_players',
    description='Maximum amount of connected players',
    default=32
)

DCS_SERVER_STARTUP_TIME = elib_config.ConfigValueInteger(
    'dcs_server', 'startup_time',
    description='Period of time, in seconds, the server is allowed to spend starting the multiplayer server.'
                'Any longer and an alert will be thrown.',
    default=120
)

DCS_SERVER_REPORT_ROLE_CHANGE = elib_config.ConfigValueString(
    'dcs_server', 'report_role_change',
    description='Displays notification when a client changes role (valid values: "true", "false")',
    default='true'
)

DCS_SERVER_REPORT_CONNECT = elib_config.ConfigValueString(
    'dcs_server', 'report_connect',
    description='Displays notification when a client connects to the server (valid values: "true", "false")',
    default='true'
)

DCS_SERVER_REPORT_EJECT = elib_config.ConfigValueString(
    'dcs_server', 'report_eject',
    description='Displays notification when a client ejects (valid values: "true", "false")',
    default='false'
)

DCS_SERVER_REPORT_KILL = elib_config.ConfigValueString(
    'dcs_server', 'report_kill',
    description='Displays notification when a client kills an object (valid values: "true", "false")',
    default='false'
)

DCS_SERVER_REPORT_TAKEOFF = elib_config.ConfigValueString(
    'dcs_server', 'report_takeoff',
    description='Displays notification when a client takes off (valid values: "true", "false")',
    default='false'
)

DCS_SERVER_REPORT_crash = elib_config.ConfigValueString(
    'dcs_server', 'report_crash',
    description='Displays notification when a client crashes their airplane (valid values: "true", "false")',
    default='false'
)

DCS_SERVER_REQUIRE_PURE_CLIENTS = elib_config.ConfigValueString(
    'dcs_server', 'require_pure_clients',
    description='Prevents modded clients from joining the server (valid values: "true", "false")',
    default='false'
)

DCS_SERVER_EXPORT_OWN_SHIP = elib_config.ConfigValueString(
    'dcs_server', 'allow_export_own_ship',
    description='Allow export of client\'s own ship data (valid values: "true", "false")',
    default='false'
)

DCS_SERVER_EXPORT_ALL = elib_config.ConfigValueString(
    'dcs_server', 'allow_export_all',
    description='Allow export of all objects data (valid values: "true", "false")',
    default='false'
)

DCS_SERVER_EXPORT_SENSOR = elib_config.ConfigValueString(
    'dcs_server', 'allow_export_sensor',
    description='Allow export of sensor data (valid values: "true", "false")',
    default='false'
)

DCS_SERVER_PASSWORD = elib_config.ConfigValueString(
    'dcs_server', 'password',
    description='DCS server password',
)

DCS_SERVER_PAUSE_ON_LOAD = elib_config.ConfigValueString(
    'dcs_server', 'pause_on_load',
    description='Start the server paused (valid values: "true", "false")',
    default='false'
)

DCS_SERVER_PAUSE_WITHOUT_CLIENT = elib_config.ConfigValueString(
    'dcs_server', 'pause_without_client',
    description='Pause the server when the last client disconnects (valid values: "true", "false")',
    default='false'
)

DCS_SERVER_RESTART_WITHOUT_CLIENT = elib_config.ConfigValueString(
    'dcs_server', 'restart_without_client',
    description='Restart DCS when the last client disconnects (valid values: "true", "false")',
    default='false'
)

DCS_SERVER_IS_PUBLIC = elib_config.ConfigValueString(
    'dcs_server', 'public',
    description='Whether the server will be shown in the public multiplayer lobby or not '
                '(valid values: "true", "false")',
    default='true'
)

DCS_SERVER_CLIENT_OUTBOUND_LIMIT = elib_config.ConfigValueInteger(
    'dcs_server', 'client_outbound_limit',
    description='Limit, in bytes, for client outbound rate',
    default=0
)

DCS_SERVER_CLIENT_INBOUND_LIMIT = elib_config.ConfigValueInteger(
    'dcs_server', 'client_inbound_limit',
    description='Limit, in bytes, for client inbound rate',
    default=0
)
