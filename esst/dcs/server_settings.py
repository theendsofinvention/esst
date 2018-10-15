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

from esst import FS, LOGGER, utils, DCSServerConfig

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
        is_public=str(DCSServerConfig.public()).lower(),
        description=DCSServerConfig.description(),
        require_pure_textures=str(DCSServerConfig.requires_pure_textures()).lower(),
        allow_change_tailno=str(DCSServerConfig.allow_change_tail_number()).lower(),
        allow_ownship_export=str(DCSServerConfig.allow_export_own_ship()).lower(),
        allow_object_export=str(DCSServerConfig.allow_export_objects()).lower(),
        pause_on_load=str(DCSServerConfig.pause_on_load()).lower(),
        allow_sensor_export=str(DCSServerConfig.allow_export_sensors()).lower(),
        event_Takeoff=str(DCSServerConfig.report_takeoff()).lower(),
        pause_without_clients=str(DCSServerConfig.pause_without_client()).lower(),
        client_outbound_limit=DCSServerConfig.outbound_limit(),
        client_inbound_limit=DCSServerConfig.inbound_limit(),
        event_Role=str(DCSServerConfig.report_role_change()).lower(),
        allow_change_skin=str(DCSServerConfig.allow_change_skin()).lower(),
        event_Connect=str(DCSServerConfig.report_connect()).lower(),
        event_Ejecting=str(DCSServerConfig.report_eject()).lower(),
        event_Kill=str(DCSServerConfig.report_kill()).lower(),
        event_Crash=str(DCSServerConfig.report_crash()).lower(),
        resume_mode=DCSServerConfig.pause_resume_mode(),
        maxPing=DCSServerConfig.max_ping(),
        require_pure_models=str(DCSServerConfig.requires_pure_models()).lower(),
        require_pure_clients=str(DCSServerConfig.requires_pure_clients()).lower(),
        name=DCSServerConfig.name(),
        port=DCSServerConfig.port(),
        password=DCSServerConfig.password(),
        bind_address=DCSServerConfig.bind_address(),
        maxPlayers=DCSServerConfig.max_players()
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
