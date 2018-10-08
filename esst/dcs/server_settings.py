# coding=utf-8
"""
Manages "Saved Games/DCS/Config/serverSettings.lua"
"""
import pprint
import re
import sys
import typing
from pathlib import Path

from jinja2 import Template

from esst import DCSServerConfig, FS, LOGGER, utils

_CURRENT_MIS_RE = re.compile(r'^.*\[1\] = "(?P<mission_path>.*)",$')


def _get_server_settings_path() -> Path:
    if not FS.dcs_server_settings:
        LOGGER.error('FS.dcs_server_settings undefined')
        sys.exit(1)
    if not FS.dcs_server_settings.exists():
        LOGGER.error('please start a DCS server at least once before using ESST')
        sys.exit(1)
    return FS.dcs_server_settings


def write_server_settings(mission_file_path: typing.Optional[str] = None) -> None:
    """
    Write "serverSettings.lua"
    :param mission_file_path: path to the mission file to set as active
    :type mission_file_path: str or None
    """
    LOGGER.debug('writing server settings')
    if mission_file_path is None:
        LOGGER.debug('no mission file given, using current mission')
        _mission_file_path = _get_current_mission_path()
    else:
        _mission_file_path = mission_file_path
    LOGGER.debug('mission file path: %s', _mission_file_path)
    template_option = dict(
        mission_file_path=_mission_file_path,
        passwd=DCSServerConfig.DCS_SERVER_PASSWORD(),
        name=DCSServerConfig.DCS_SERVER_NAME(),
        max_players=DCSServerConfig.DCS_SERVER_MAX_PLAYERS(),
        pause_on_load=DCSServerConfig.DCS_SERVER_PAUSE_ON_LOAD(),
        pause_without_clients=DCSServerConfig.DCS_SERVER_PAUSE_WITHOUT_CLIENT(),
        event_role=DCSServerConfig.DCS_SERVER_REPORT_ROLE_CHANGE(),
        allow_ownship_export=DCSServerConfig.DCS_SERVER_EXPORT_OWN_SHIP(),
        allow_object_export=DCSServerConfig.DCS_SERVER_EXPORT_ALL(),
        event_connect=DCSServerConfig.DCS_SERVER_REPORT_CONNECT(),
        event_ejecting=DCSServerConfig.DCS_SERVER_REPORT_EJECT(),
        event_kill=DCSServerConfig.DCS_SERVER_REPORT_KILL(),
        event_takeoff=DCSServerConfig.DCS_SERVER_REPORT_TAKEOFF(),
        client_outbound_limit=DCSServerConfig.DCS_SERVER_CLIENT_OUTBOUND_LIMIT(),
        client_inbound_limit=DCSServerConfig.DCS_SERVER_CLIENT_INBOUND_LIMIT(),
        event_crash=DCSServerConfig.DCS_SERVER_REPORT_crash(),
        resume_mode=1,
        allow_sensor_export=DCSServerConfig.DCS_SERVER_EXPORT_SENSOR(),
        is_public=DCSServerConfig.DCS_SERVER_IS_PUBLIC(),
    )
    LOGGER.debug('rendering settings.lua template with options\n%s', pprint.pformat(template_option))
    content = Template(utils.read_template('settings.lua')).render(**template_option)
    server_settings = _get_server_settings_path()
    LOGGER.debug('settings file path: %s', server_settings)
    utils.create_versioned_backup(server_settings)
    server_settings.write_text(content)


def _get_current_mission_path() -> str:
    """
    Extracts the path of the current (first) defined mission in "serverSettings.lua"

    :return: path to the mission
    :rtype: str
    """
    server_settings = _get_server_settings_path()
    text: str = Path(server_settings).read_text()
    for line in text.split('\n'):
        match = _CURRENT_MIS_RE.match(line)
        if match:
            return match.group('mission_path')
    LOGGER.error('please start a DCS server at least once before using ESST')
    sys.exit(1)
