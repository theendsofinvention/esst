# coding=utf-8
"""
Manages config values for DCS server
"""

import elib_config

from esst.sentry.sentry_context import SentryConfigContext


class DCSServerConfig(SentryConfigContext):
    """
    DCS server config values
    """
    public = elib_config.ConfigValueBool(
        'dcs_server', 'public',
        description='Whether the server will be shown in the public multiplayer lobby or not '
                    '(valid values: true, false)',
        default=True
    )

    requires_pure_clients = elib_config.ConfigValueBool(
        'dcs_server', 'integrity_check', 'requires_pure_client',
        description='Integrity check that prevents player from joining the server if they have modded scripts '
                    'in the units database. '
                    'Please see https://forums.eagle.ru/showthread.php?p=3387574 for more info about the '
                    'integrity check',
        default=False
    )

    requires_pure_textures = elib_config.ConfigValueBool(
        'dcs_server', 'integrity_check', 'requires_pure_textures',
        description='Integrity check that prevents player from joining the server if they have modded textures. '
                    'Please see https://forums.eagle.ru/showthread.php?p=3387574 for more info about the '
                    'integrity check',
        default=False
    )

    requires_pure_models = elib_config.ConfigValueBool(
        'dcs_server', 'integrity_check', 'requires_pure_models',
        description='Integrity check that prevents player from joining the server if they have modded models. '
                    'Please see https://forums.eagle.ru/showthread.php?p=3387574 for more info about the '
                    'integrity check',
        default=False
    )

    # SHUFFLE_MISSION_LIST = elib_config.ConfigValueBool(
    #     'dcs_server', 'shuffle_mission_list',
    #     description='Shuffles the list of missions on the server',
    #     default=False
    # )

    description = elib_config.ConfigValueString(
        'dcs_server', 'description',
        description='DCS server description (WARNING: this seems to be an undocumented DCS feature; use at your '
                    'own risk)',
        default=''
    )

    allow_change_tail_number = elib_config.ConfigValueBool(
        'dcs_server', 'allow', 'change_tail_number',
        description='Allow players to change their own tail number.',
        default=True
    )

    allow_change_skin = elib_config.ConfigValueBool(
        'dcs_server', 'allow', 'change_skin',
        description='Allow players to change their own skin.',
        default=True
    )

    allow_export_own_ship = elib_config.ConfigValueBool(
        'dcs_server', 'export', 'own_ship',
        description='Allow export of data about players own aircraft.',
        default=True
    )

    allow_export_objects = elib_config.ConfigValueBool(
        'dcs_server', 'export', 'objects',
        description='Allow export of data about objects in DCS World.',
        default=True
    )

    allow_export_sensors = elib_config.ConfigValueBool(
        'dcs_server', 'export', 'sensors',
        description='Allow export of data from onboard sensors.',
        default=True
    )

    pause_on_load = elib_config.ConfigValueBool(
        'dcs_server', 'pause', 'on_load',
        description='Start the server in a paused state.',
        default=False
    )

    pause_without_client = elib_config.ConfigValueBool(
        'dcs_server', 'pause', 'without_client',
        description='Automatically pause the server when the last client disconnects.',
        default=False
    )

    pause_resume_mode = elib_config.ConfigValueInteger(
        'dcs_server', 'pause', 'resume_mode',
        description='Select the "resume" (i.e. un-pause) behaviour for the server. '
                    '0: manually pause/un-pause, '
                    '1: un-pause on server start, '
                    '2: un-pause when a player connects to the server',
        default=1
    )

    report_takeoff = elib_config.ConfigValueBool(
        'dcs_server', 'report', 'takeoff',
        description='Display a server-wide message when a player takes off.',
        default=False
    )

    report_role_change = elib_config.ConfigValueBool(
        'dcs_server', 'report', 'role_change',
        description='Display a server-wide message when a player changes role.',
        default=False
    )

    report_connect = elib_config.ConfigValueBool(
        'dcs_server', 'report', 'connection',
        description='Display a server-wide message when a player connects to the server.',
        default=True
    )

    report_eject = elib_config.ConfigValueBool(
        'dcs_server', 'report', 'ejection',
        description='Display a server-wide message when a player ejects.',
        default=False
    )

    report_kill = elib_config.ConfigValueBool(
        'dcs_server', 'report', 'kill',
        description='Display a server-wide message when a player destroys another object.',
        default=False
    )

    report_crash = elib_config.ConfigValueBool(
        'dcs_server', 'report', 'crash',
        description='Display a server-wide message when a player crashes their own aircraft.',
        default=False
    )

    outbound_limit = elib_config.ConfigValueInteger(
        'dcs_server', 'connection', 'outbound_rate_limit',
        description='Limit, in bytes, for client outbound rate (0 means deactivated).',
        default=0
    )

    inbound_limit = elib_config.ConfigValueInteger(
        'dcs_server', 'connection', 'inbound_rate_limit',
        description='Limit, in bytes, for client inbound rate (0 means deactivated).',
        default=0
    )

    max_ping = elib_config.ConfigValueInteger(
        'dcs_server', 'connection', 'max_ping',
        description='Maximum allowed client ping in milliseconds (0 to disable).',
        default=0
    )

    port = elib_config.ConfigValueString(
        'dcs_server', 'connection', 'port',
        description='Port the DCS server will be listening to.',
        default='10308'
    )

    bind_address = elib_config.ConfigValueString(
        'dcs_server', 'connection', 'bind_address',
        description='Binds the DCS server to a specific network interface (leave empty to allow all interfaces).',
        default=''
    )

    name = elib_config.ConfigValueString(
        'dcs_server', 'name',
        description='Public name of the DCS server.'
    )

    password = elib_config.ConfigValueString(
        'dcs_server', 'password',
        description='Prevent players without password from connecting to the server.',
        default=''
    )

    max_players = elib_config.ConfigValueInteger(
        'dcs_server', 'max_player_count',
        description='Maximum amount of players allowed on the server at the same time.',
        default=16
    )
