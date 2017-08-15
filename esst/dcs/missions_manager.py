# coding=utf-8
"""
Manages missions for the server
"""

import os
import sys
import json
import shutil
import time

import blinker
import github3
import humanize
import requests
from jinja2 import Template

from esst.core.config import CFG
from esst.core.logger import MAIN_LOGGER
from esst.core.status import Status
from esst.core.run import do_ex

LOGGER = MAIN_LOGGER.getChild(__name__)

# noinspection SpellCheckingInspection
LUA_TEMPLATE = Template("""cfg =
{
    ["isPublic"] = true,
    ["missionList"] =
    {
        [1] = "{{ mission_file_path }}",
    }, -- end of ["missionList"]
    ["bind_address"] = "",
    ["port"] = "10308",
    ["advanced"] =
    {
        ["event_Role"] = false,
        ["allow_ownship_export"] = true,
        ["allow_object_export"] = true,
        ["pause_on_load"] = false,
        ["event_Connect"] = true,
        ["event_Ejecting"] = false,
        ["event_Kill"] = false,
        ["event_Takeoff"] = false,
        ["pause_without_clients"] = false,
        ["client_outbound_limit"] = 0,
        ["event_Crash"] = false,
        ["client_inbound_limit"] = 0,
        ["resume_mode"] = 1,
        ["allow_sensor_export"] = true,
    }, -- end of ["advanced"]
    ["password"] = "{{ passwd }}",
    ["require_pure_clients"] = false,
    ["version"] = 1,
    ["description"] = "",
    ["name"] = "{{ name }}",
    ["listLoop"] = false,
    ["listShuffle"] = false,
    ["maxPlayers"] = {{ max_players }},
} -- end of cfg

""")

def _mission_not_found(mission_path):
    LOGGER.error(f'mission not found: {mission_path}')


def _sanitize_path(path):
    return path.replace('\\', '/')


def _get_settings_file_path():
    return _sanitize_path(os.path.join(CFG.saved_games_dir, 'Config/serverSettings.lua'))


def _backup_settings_file():
    backup_file_path = _get_settings_file_path() + '.backup'
    if not os.path.exists(backup_file_path):
        LOGGER.debug('making of backup of the settings')
        shutil.copy(_get_settings_file_path(), backup_file_path)


def set_active_mission(mission_file_path: str, metar: str = 'unknown'):
    """
    Sets the mission as active in "serverSettings.lua"

    Args:
        mission_file_path: complete path to the MIZ file
        metar: METAR string for this mission
    """
    LOGGER.info(f'setting active mission to: {os.path.basename(mission_file_path)}')
    mission_file_path = mission_file_path.replace('\\', '/')
    content = LUA_TEMPLATE.render(
        mission_file_path=mission_file_path,
        passwd=CFG.dcs_server_password,
        name=CFG.dcs_server_name,
        max_players=CFG.dcs_server_max_players,
    )
    settings_file = _get_settings_file_path()
    _backup_settings_file()
    with open(settings_file, 'w') as handle:
        handle.write(content)
    Status.metar = metar


def set_active_mission_from_name(mission_name: str, load: bool = False):
    """
    Sets the mission as active in serverSettings.lua and optionally restarts the server

    Args:
        mission_name: mission name as string (not the full path)
        load: whether or not to restart the server
    """
    mission_path = _get_mission_path(mission_name)
    if not os.path.exists(mission_path):
        _mission_not_found(mission_path)
    else:
        set_active_mission(mission_path)
        if load:
            blinker.signal('dcs command').send('__name__', cmd='restart')


def _get_mission_dir() -> str:
    """
    Returns: ESST mission dir path
    """
    mission_dir = os.path.join(CFG.saved_games_dir, 'Missions/ESST')
    if not os.path.exists(mission_dir):
        LOGGER.debug(f'creating directory: {mission_dir}')
        os.makedirs(mission_dir)
    return _sanitize_path(mission_dir)


def _get_mission_path(mission_file_name):
    return _sanitize_path(os.path.join(_get_mission_dir(), mission_file_name))


def _get_mission_path_with_RL_weather(mission_file_name):
    mission_path = _get_mission_path(mission_file_name)
    dirname = os.path.dirname(mission_path)
    file, ext = os.path.splitext(mission_path)
    return os.path.join(dirname, f'{file}_RLWX{ext}')


def _create_mission_path(mission_name):
    return _sanitize_path(os.path.join(_get_mission_dir(), mission_name))


def set_weather(ctx: dict, icao_code: str, mission_name: str = None):
    if mission_name is None:
        if Status.mission_file != 'unknown':
            LOGGER.debug(f'using active mission: {Status.mission_file}')
            mission_path = Status.mission_file
        else:
            LOGGER.error('no active mission; please load a mission first')
            return
    else:
        mission_path = _get_mission_path(mission_name)
    if not os.path.exists(mission_path):
        _mission_not_found(mission_path)
        return
    LOGGER.info(f'setting weather from {icao_code} to {mission_path}')
    output_path = _get_mission_path_with_RL_weather(mission_path)
    emft = os.path.join(os.path.dirname(sys.executable), 'Scripts/emft.exe')
    out, err, ret = do_ex(
        [
            emft, '-v', 'set_weather',
            '-s', icao_code,
            '-i', mission_path,
            '-o', output_path,
        ]
    )
    if ret:
        LOGGER.error('unable to set weather')
        LOGGER.error(err)
    else:
        result = json.loads(out)
        if result['status'] == 'success':
            LOGGER.info(f'successfully set the weather on mission: {result["to"]}\n'
                        f'METAR is: {result["metar"].upper()}')
            set_active_mission(result["to"], metar=result['metar'])
            blinker.signal('dcs command').send('__name__', cmd='restart')
        elif result['status'] == 'failed':
            LOGGER.error(f'setting weather failed:\n{result["error"]}')
        else:
            LOGGER.error(f'unknown status: {result["status"]}')



def get_latest_mission_from_github(ctx):
    """
    Downloads the latest mission from a Github repository

    The repository needs to have releases (tagged)
    The function will download the first MIZ file found in the latest release
    """
    if CFG.auto_mission_github_repo and CFG.auto_mission_github_owner:
        LOGGER.debug('looking for newer mission file')
        github = github3.GitHub(token=CFG.auto_mission_github_token)
        repo = github.repository(CFG.auto_mission_github_owner, CFG.auto_mission_github_repo)
        rel = repo.latest_release()
        LOGGER.debug(f'release tag: {rel.tag_name}')
        assets = list(rel.assets(1))
        for asset in assets:
            if asset.name.endswith('.miz'):
                LOGGER.debug(f'found a mission file: {asset.name}')
                local_file = _create_mission_path(asset.name)
                if not os.path.exists(local_file):
                    LOGGER.info(f'downloading new mission: {asset.name}')
                    asset.download(local_file)
                set_active_mission(local_file)


def download_mission_from_discord(discord_attachment, overwrite=False, load=False):
    """
    Downloads a mission from a discord message attachment

    Args:
        discord_attachment: url to download the mission from
        overwrite: whether or not to overwrite an existing file
        load: whether or not to restart the server with the downloaded mission

    Returns:

    """
    url = discord_attachment['url']
    size = discord_attachment['size']
    filename = discord_attachment['filename']
    local_file = _get_mission_path(filename)
    overwriting = ''
    if os.path.exists(local_file):
        if overwrite:
            overwriting = ' (replacing existing file)'
        else:
            LOGGER.warning(f'this mission already exists: {local_file}\n'
                           f'use "overwrite" to replace it')
            return
    LOGGER.info(f'downloading: {filename} ({humanize.naturalsize(size)}) {overwriting}')
    with requests.get(url) as response:
        with open(local_file, 'wb') as out_file:
            out_file.write(response.content)
    if load:
        LOGGER.info(f'restarting the server with this mission')
        set_active_mission(local_file)
        blinker.signal('dcs command').send('__name__', cmd='restart')
    else:
        LOGGER.info(f'download successful, mission is now available')


def list_available_missions():
    """
    Generator that yields available mission in ESST's mission dir
    """
    for file in os.listdir(_get_mission_dir()):
        if file.endswith('.miz'):
            yield file
