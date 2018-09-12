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

from esst import core, utils

LOGGER = core.MAIN_LOGGER.getChild(__name__)
_CURRENT_MIS_RE = re.compile(r'^.*\[1\] = "(?P<mission_path>.*)",$')


def write_server_settings(mission_file_path: typing.Optional[str] = None) -> None:
    """
    Write "serverSettings.lua"
    :param mission_file_path: path to the mission file to set as active
    :type mission_file_path: str
    """
    if mission_file_path is None:
        mission_file_path = _get_current_mission_path()
    template_option = dict(
        mission_file_path=mission_file_path,
        passwd=core.CFG.dcs_server_password,
        name=core.CFG.dcs_server_name,
        max_players=core.CFG.dcs_server_max_players,
        pause_on_load=core.CFG.dcs_server_pause_on_load,
        pause_without_clients=core.CFG.dcs_server_pause_without_clients,
        event_role=core.CFG.dcs_server_event_role,
        allow_ownship_export=core.CFG.dcs_server_allow_ownship_export,
        allow_object_export=core.CFG.dcs_server_allow_object_export,
        event_connect=core.CFG.dcs_server_event_connect,
        event_ejecting=core.CFG.dcs_server_event_ejecting,
        event_kill=core.CFG.dcs_server_event_kill,
        event_takeoff=core.CFG.dcs_server_event_takeoff,
        client_outbound_limit=core.CFG.dcs_server_client_outbound_limit,
        client_inbound_limit=core.CFG.dcs_server_client_inbound_limit,
        event_crash=core.CFG.dcs_server_event_crash,
        resume_mode=core.CFG.dcs_server_resume_mode,
        allow_sensor_export=core.CFG.dcs_server_allow_sensor_export,
        is_public=core.CFG.dcs_server_is_public,
    )
    LOGGER.debug(f'rendering settings.lua template with options\n{pprint.pformat(template_option)}')
    content = Template(utils.read_template('settings.lua')).render(**template_option)
    settings_file_path = core.FS.dcs_server_settings
    LOGGER.debug(f'settings file path: {settings_file_path}')
    utils.create_versioned_backup(settings_file_path)
    settings_file_path.write_text(content)


def _get_current_mission_path() -> str:
    """
    Extracts the path of the current (first) defined mission in "serverSettings.lua"

    :return: path to the mission
    :rtype: str
    """
    try:
        text: str = Path(core.FS.dcs_server_settings).read_text()
    except FileNotFoundError:
        LOGGER.error('please start a DCS server at least once before using ESST')
        sys.exit(1)
    else:
        for line in text.split('\n'):
            match = _CURRENT_MIS_RE.match(line)
            if match:
                return match.group('mission_path')

        LOGGER.error('please start a DCS server at least once before using ESST')
        sys.exit(1)
