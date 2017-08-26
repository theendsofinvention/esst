# coding=utf-8
"""
Manages missions for the server
"""

import asyncio
import os
import shutil

import github3
import humanize
import requests
from emiz.weather import build_metar_from_mission, retrieve_metar, set_weather_from_metar_str
from jinja2 import Template

from esst.commands import DCS
from esst.core import CFG, CTX, MAIN_LOGGER, Status
from esst.utils import read_template

LOGGER = MAIN_LOGGER.getChild(__name__)


def _mission_not_found(mission_path):
    LOGGER.error(f'mission not found: {mission_path}')


def _sanitize_path(path):
    return path.replace('\\', '/')


def _ensure_mission_file(path):
    path = os.path.abspath(path)
    if os.path.exists(path):
        return _sanitize_path(path)

    _mission_not_found(path)


def _get_settings_file_path():
    return _sanitize_path(os.path.join(CFG.saved_games_dir, 'Config/serverSettings.lua'))


def _backup_settings_file():
    backup_file_path = _get_settings_file_path() + '.backup'
    if not os.path.exists(backup_file_path):
        LOGGER.debug('making of backup of the settings')
        shutil.copy(_get_settings_file_path(), backup_file_path)


def set_active_mission(mission_file_path: str, metar: str = None, load: bool = False):
    """
    Sets the mission as active in "serverSettings.lua"

    Args:
        mission_file_path: complete path to the MIZ file
        metar: METAR string for this mission
    """
    if not _ensure_mission_file(mission_file_path):
        return

    LOGGER.info(f'setting active mission to: {os.path.basename(mission_file_path)}')
    mission_file_path = mission_file_path.replace('\\', '/')
    content = Template(read_template('settings.template')).render(
        mission_file_path=mission_file_path,
        passwd=CFG.dcs_server_password,
        name=CFG.dcs_server_name,
        max_players=CFG.dcs_server_max_players,
    )

    _backup_settings_file()
    with open(_get_settings_file_path(), 'w') as handle:
        handle.write(content)

    if metar is None:
        LOGGER.debug(f'building metar for mission: {mission_file_path}')
        metar = build_metar_from_mission(mission_file_path, icao='UGTB')
        LOGGER.info(f'metar for {os.path.basename(mission_file_path)}:\n{metar}')
    Status.metar = metar

    if load:
        DCS.restart()


def set_active_mission_from_name(mission_name: str, load: bool = False):
    """
    Sets the mission as active in serverSettings.lua and optionally restarts the server

    Args:
        mission_name: mission name as string (not the full path)
        load: whether or not to restart the server
    """
    set_active_mission(get_path_from_name(mission_name), load=load)


def _get_mission_dir() -> str:
    """
    Returns: ESST mission dir path
    """
    mission_dir = os.path.join(CFG.saved_games_dir, 'Missions/ESST')
    if not os.path.exists(mission_dir):
        LOGGER.debug(f'creating directory: {mission_dir}')
        os.makedirs(mission_dir)
    return _sanitize_path(mission_dir)


def get_path_from_name(mission_file_name):
    return _sanitize_path(os.path.join(_get_mission_dir(), mission_file_name))


def _get_mission_path_with_RL_weather(mission_file_name):
    mission_path = get_path_from_name(mission_file_name)
    dirname = os.path.dirname(mission_path)
    file, ext = os.path.splitext(mission_path)
    return os.path.join(dirname, f'{file}_RLWX{ext}')


def _create_mission_path(mission_name):
    return _sanitize_path(os.path.join(_get_mission_dir(), mission_name))


def __set_weather(metar_str, mission_path, output_path):
    try:
        return set_weather_from_metar_str(metar_str, mission_path, output_path)
    except Exception:
        LOGGER.exception('Set weather failed')
        return {
            'status': 'failed',
            'error': 'Uncaught exception while setting the weather, please see the log file'
        }


async def set_weather(icao_code: str, mission_name: str = None):
    if mission_name is None:
        if Status.mission_file and Status.mission_file != 'unknown':
            LOGGER.debug(f'using active mission: {Status.mission_file}')
            mission_path = Status.mission_file.replace('_RLWX', '')
        else:
            LOGGER.error('no active mission; please load a mission first')
            return
    else:
        mission_path = get_path_from_name(mission_name)
    if not os.path.exists(mission_path):
        _mission_not_found(mission_path)
        return
    try:
        metar_str = retrieve_metar(icao_code)
    except FileNotFoundError:
        LOGGER.error(f'no METAR found for station: {icao_code}\n'
                     f'Go to "http://tgftp.nws.noaa.gov/data/observations/metar/stations/" '
                     f'for a list of valid stations')
        return

    DCS.cannot_start()
    DCS.kill()
    while Status.dcs_application != 'not running':
        await asyncio.sleep(1)
    LOGGER.info(f'setting weather from {icao_code} to {mission_path}')
    output_path = _get_mission_path_with_RL_weather(mission_path)

    result = await CTX.loop.run_in_executor(
        None,
        __set_weather,
        metar_str, mission_path, output_path
    )

    if result['status'] == 'success':
        LOGGER.info(f'successfully set the weather on mission: {result["to"]}\n'
                    f'METAR is: {result["metar"].upper()}')
        set_active_mission(result["to"], metar=result['metar'], load=True)

    elif result['status'] == 'failed':
        LOGGER.error(f'setting weather failed:\n{result["error"]}')

    else:
        LOGGER.error(f'unknown status: {result["status"]}')

    DCS.can_start()


def get_latest_mission_from_github():
    """
    Downloads the latest mission from a Github repository

    The repository needs to have releases (tagged)
    The function will download the first MIZ file found in the latest release
    """
    if CTX.dcs_auto_mission:
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
        else:
            LOGGER.error('no config values given for [auto mission]')
    else:
        LOGGER.debug('skipping mission update')


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
    local_file = get_path_from_name(filename)

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
        set_active_mission(local_file, load=True)
    else:
        LOGGER.info(f'download successful, mission is now available')


def list_available_missions():
    """
    Generator that yields available mission in ESST's mission dir
    """
    for file in os.listdir(_get_mission_dir()):
        if file.endswith('.miz') and not '_RLWX.miz' in file:
            yield file


def get_running_mission():
    if Status.mission_file and Status.mission_file != 'unknown':
        if os.path.exists(Status.mission_file):
            LOGGER.debug(f'using active mission: {Status.mission_file}')
            return _sanitize_path(Status.mission_file)
        else:
            LOGGER.error(f'current mission is: "{Status.mission_file}", but that file does not exist')
    else:
        LOGGER.error('no active mission; please load a mission first (or just wait a moment for the server to start)')
