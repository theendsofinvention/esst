# coding=utf-8
"""
Manages missions for the server
"""

import os
import typing

import humanize
import requests
from emiz.weather import build_metar_from_mission
from jinja2 import Template

from esst.commands import DCS
from esst.core import CFG, CTX, MAIN_LOGGER, Status
from esst.utils import create_versionned_backup, get_latest_release, read_template

LOGGER = MAIN_LOGGER.getChild(__name__)

MISSION_FOLDER = os.path.join(CFG.saved_games_dir, 'Missions/ESST')
if not os.path.exists(MISSION_FOLDER):
    LOGGER.debug(f'creating directory: {MISSION_FOLDER}')
    os.makedirs(MISSION_FOLDER)


class MissionPath:
    """
    Represents a MIZ file managed by ESST
    """

    def __init__(self, mission: str):
        if not os.path.isabs(mission):
            self._path = os.path.join(MISSION_FOLDER, mission)
        else:
            self._path = mission

    @property
    def name(self):
        """

        Returns: basename

        """
        return os.path.basename(self._path)

    @property
    def rlwx(self):
        """

        Returns: path to the MIZ file with a "_ESST" suffixed to its name

        """
        if '_ESST.miz' in self.path:
            return self

        dirname = os.path.dirname(self._path)
        file, ext = os.path.splitext(self._path)
        return MissionPath(_sanitize_path(os.path.join(dirname, f'{file}_ESST{ext}')))

    def strip_suffix(self):
        """

        Returns: path to a MIZ file without the "_ESST" suffix

        """
        if '_ESST' not in os.path.basename(self.path):
            return self

        return MissionPath(
            os.path.join(
                os.path.dirname(self.path),
                os.path.basename(self.path).replace('_ESST', '')
            )
        )

    @property
    def path(self):
        """

        Returns: path to the MIZ file

        """
        return _sanitize_path(self._path)

    def set_as_active(self, metar: str = None):
        """
        Write the settings file to set this mission as active
        Args:
            metar: metar string; if not provided,  will be inferred from MIZ file

        """

        LOGGER.info(f'setting active mission to: {self.name}')
        if not self:
            LOGGER.error(f'mission file not found: {self.path}')
            return
        content = Template(read_template('settings.lua')).render(
            mission_file_path=self.path,
            passwd=CFG.dcs_server_password,
            name=CFG.dcs_server_name,
            max_players=CFG.dcs_server_max_players,
        )
        create_versionned_backup(_get_settings_file_path())
        with open(_get_settings_file_path(), 'w') as handle:
            handle.write(content)

        if metar is None:
            LOGGER.debug(f'building metar for mission: {self.path}')
            metar = build_metar_from_mission(self.path, icao='XXXX')
            LOGGER.info(f'metar for {os.path.basename(self.path)}:\n{metar}')
        Status.metar = metar

    def __str__(self):
        return _sanitize_path(self._path)

    def __repr__(self):
        return f'MissionPath({self._path})'

    def __bool__(self):
        return os.path.exists(self._path)


def _sanitize_path(path):
    return path.replace('\\', '/')


def _get_settings_file_path():
    return _sanitize_path(os.path.join(CFG.saved_games_dir, 'Config/serverSettings.lua'))


def set_active_mission(mission: str, metar: str = None):
    """
    Sets the mission as active in "serverSettings.lua"

    Args:
        mission: path or name of the MIZ file
        metar: METAR string for this mission
    """
    mission = MissionPath(mission)
    mission.set_as_active(metar)


def delete(mission: MissionPath):
    """
    Removes a mission from the filesystem.

    Also removes leftover RLWX artifacts

    Args:
        mission: MissionPath instance to remove

    """
    if os.path.exists(mission.path):
        LOGGER.info(f'removing: {mission.path}')
        os.unlink(mission.path)
    if os.path.exists(mission.rlwx.path):
        LOGGER.info(f'removing: {mission.rlwx.path}')
        os.unlink(mission.rlwx.path)


def get_latest_mission_from_github():
    """
    Downloads the latest mission from a Github repository

    The repository needs to have releases (tagged)
    The function will download the first MIZ file found in the latest release
    """
    if CTX.dcs_auto_mission:
        DCS.cannot_start()
        if CFG.auto_mission_github_repo and CFG.auto_mission_github_owner:
            LOGGER.debug('looking for newer mission file')
            latest_version, asset_name, download_url = get_latest_release(
                CFG.auto_mission_github_owner, CFG.auto_mission_github_repo
            )
            LOGGER.debug(f'latest release: {latest_version}')
            local_file = MissionPath(f'AUTO_{asset_name}')
            if not local_file:
                LOGGER.info(f'downloading new mission: {asset_name}')
                req = requests.get(download_url)
                if req.ok:
                    with open(str(local_file.path), 'wb') as stream:
                        stream.write(req.content)
                    local_file.set_as_active()
                else:
                    LOGGER.error('failed to download latest mission')
        else:
            LOGGER.error('no config values given for [auto mission]')
        DCS.can_start()
    else:
        LOGGER.debug('skipping mission update')


def download_mission_from_discord(discord_attachment, overwrite=False, load=False, force=False):
    """
    Downloads a mission from a discord message attachment

    Args:
        discord_attachment: url to download the mission from
        overwrite: whether or not to overwrite an existing file
        load: whether or not to restart the server with the downloaded mission
    """
    url = discord_attachment['url']
    size = discord_attachment['size']
    filename = discord_attachment['filename']
    local_file = MissionPath(filename)

    overwriting = ''
    if local_file:
        if overwrite:
            overwriting = ' (replacing existing file)'
        else:
            LOGGER.warning(f'this mission already exists: {local_file.path}\n'
                           f'use "overwrite" to replace it')
            return

    LOGGER.info(
        f'downloading: {filename} ({humanize.naturalsize(size)}) {overwriting}')
    with requests.get(url) as response:
        with open(local_file.path, 'wb') as out_file:
            out_file.write(response.content)

    if load:
        local_file.set_as_active()
        LOGGER.info(f'restarting the server with this mission')
        DCS.restart(force=force)
    else:
        LOGGER.info(f'download successful, mission is now available')


def list_available_missions():
    """
    Generator that yields available mission in ESST's mission dir
    """
    count = 1
    for file in os.listdir(MISSION_FOLDER):
        if file.endswith('.miz') and '_ESST.miz' not in file:
            yield count, file
            count += 1


def get_running_mission() -> typing.Union['MissionPath', str]:
    """

    Returns: currently running mission as a MissionPath instance

    """
    if Status.mission_file and Status.mission_file != 'unknown':
        mission = MissionPath(Status.mission_file)
        if mission:
            LOGGER.debug(f'returning active mission: {mission.name}')
            return mission

        LOGGER.error(
            f'current mission is "{mission.path}", but that file does not exist')
        return ''

    LOGGER.error('no active mission; please load a mission first '
                 '(or just wait a moment for the server to be ready)')
    return ''
