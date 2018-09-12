# coding=utf-8
"""
Manages missions for the server
"""
import sys
import typing
from pathlib import Path

import emiz.weather
import humanize
import requests

from esst import atis, commands, core, utils
from esst.dcs.server_settings import write_server_settings

LOGGER = core.MAIN_LOGGER.getChild(__name__)


def _get_mission_folder() -> Path:
    return core.FS.dcs_mission_folder


def _get_auto_mission_folder() -> Path:
    auto_mission_folder = Path(_get_mission_folder().joinpath('AUTO'))
    if not auto_mission_folder.exists():
        LOGGER.debug(f'creating directory: {auto_mission_folder}')
        auto_mission_folder.mkdir(parents=True)
    return auto_mission_folder


class MissionPath:
    """
    Represents a MIZ file managed by ESST
    """

    def __init__(self, mission: typing.Union[str, Path]) -> None:
        self._path = Path(mission)
        self._orig_name = self._path.stem

    @property
    def name(self) -> str:
        """
        Returns: path's stem
        """
        return self._path.stem

    @property
    def orig_name(self):
        """
        Returns: original name of the mission
        """
        return self._orig_name

    @property
    def auto(self) -> 'MissionPath':
        """
        Returns: MissionPath object for the auto mission
        """
        if self._path.parent == _get_auto_mission_folder():
            return self

        return MissionPath(Path(_get_auto_mission_folder()).joinpath(self._path.name))

    @property
    def path(self) -> Path:
        """
        Returns: path to the MIZ file
        """
        return self._path

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

        write_server_settings(str(self.path).replace('\\', '/'))

        if metar is None:
            LOGGER.debug(f'building metar from mission: {self.name}')
            # noinspection SpellCheckingInspection
            metar = emiz.weather.mizfile.get_metar_from_mission(str(self.path), icao='XXXX')
            LOGGER.info(f'metar for {self.name}:\n{metar}')
        else:
            atis.generate_atis(metar)
            core.Status.metar = metar

    def __str__(self):
        return str(self.path)

    def __repr__(self):
        return f'MissionPath({self._path})'

    def __bool__(self):
        return self.path.exists()


def _get_settings_file_path() -> Path:
    return core.FS.dcs_server_settings
    # return Path(core.FS.saved_games_path, 'DCS/Config/serverSettings.lua')


def set_active_mission(mission_path_as_str: str, metar: str = None):
    """
    Sets the mission as active in "serverSettings.lua"

    Args:
        mission_path_as_str: path or name of the MIZ file
        metar: METAR string for this mission
    """
    LOGGER.debug(f'setting active mission: {mission_path_as_str}')
    if metar:
        LOGGER.debug(f'using METAR: {metar}')
    mission_path = MissionPath(mission_path_as_str)
    mission_path.set_as_active(metar)


def delete(mission: MissionPath):
    """
    Removes a mission from the filesystem.

    Also removes leftover AUTO artifacts

    Args:
        mission: MissionPath instance to remove

    """
    if mission:
        LOGGER.info(f'removing: {mission.path}')
        mission.path.unlink()
    if mission.auto:
        LOGGER.info(f'removing: {mission.auto.path}')
        mission.auto.path.unlink()


def get_latest_mission_from_github():
    """
    Downloads the latest mission from a Github repository

    The repository needs to have releases (tagged)
    The function will download the first MIZ file found in the latest release
    """
    if core.CTX.dcs_auto_mission:
        LOGGER.debug('getting latest mission from Github')
        commands.DCS.block_start('loading mission')
        if core.CFG.auto_mission_github_repo and core.CFG.auto_mission_github_owner:
            LOGGER.debug('looking for newer mission file')
            latest_version, asset_name, download_url = utils.get_latest_release(
                core.CFG.auto_mission_github_owner, core.CFG.auto_mission_github_repo
            )
            LOGGER.debug(f'latest release: {latest_version}')
            local_file = MissionPath(Path(_get_mission_folder(), f'{asset_name}'))
            if not local_file:
                LOGGER.info(f'downloading new mission: {asset_name}')
                req = requests.get(download_url)
                if req.ok:
                    local_file.path.write_bytes(req.content)
                    local_file.set_as_active()
                else:
                    LOGGER.error('failed to download latest mission')
        else:
            LOGGER.error('no config values given for [auto mission]')
        commands.DCS.unblock_start('loading mission')
    else:
        LOGGER.debug('skipping mission update')


def download_mission_from_discord(discord_attachment,
                                  overwrite: bool = False,
                                  load: bool = False,
                                  force: bool = False):
    """
    Downloads a mission from a discord message attachment

    Args:
        force: force restart even with players connected
        discord_attachment: url to download the mission from
        overwrite: whether or not to overwrite an existing file
        load: whether or not to restart the server with the downloaded mission
    """
    url = discord_attachment['url']
    size = discord_attachment['size']
    filename = discord_attachment['filename']
    local_file = MissionPath(Path(_get_mission_folder(), filename))

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
        local_file.path.write_bytes(response.content)

    if load:
        if commands.DCS.there_are_connected_players() and not force:
            LOGGER.error('there are connected players; cannot restart the server now (use "force" to kill anyway)')
            return
        LOGGER.info(f'restarting the server with this mission')
        local_file.set_as_active()
        commands.DCS.restart(force=force)
    else:
        LOGGER.info(f'download successful, mission is now available')


def list_available_missions():
    """
    Generator that yields available mission in ESST's mission dir
    """
    count = 1
    for file in _get_mission_folder().glob('*.miz'):
        yield count, file
        count += 1


def get_running_mission() -> typing.Union['MissionPath', str]:
    """

    Returns: currently running mission as a MissionPath instance

    """
    mission = None
    if core.Status.mission_file and core.Status.mission_file != 'unknown':
        mission_path = Path(core.Status.mission_file)
        if mission_path.parent == 'AUTO':
            mission_path = Path(mission_path.parent.parent, mission_path.name)
        mission = MissionPath(mission_path)

    else:
        try:
            dcs_settings = Path(core.FS.dcs_server_settings).read_text()
        except FileNotFoundError:
            LOGGER.error('please start a DCS server at least once before using ESST')
            sys.exit(1)
        else:
            for line in dcs_settings.split('\n'):
                if '[1]' in line:
                    mission = MissionPath(line.split('"')[1])
                    break

    if mission:
        LOGGER.debug(f'returning active mission: {mission.name}')
        return mission

    LOGGER.error(f'current mission is "{mission}", but that file does not exist')
    return ''


def initial_setup():
    """
    Runs at the start of the DCS loop, to initialize the first mission
    """
    LOGGER.debug('initializing first mission')
    mission = get_running_mission()
    if isinstance(mission, MissionPath):
        LOGGER.info(f'building METAR for initial mission: {mission.orig_name}')
        metar = emiz.weather.mizfile.get_metar_from_mission(str(mission.path))
        core.Status.metar = metar
        atis.generate_atis(metar)
    else:
        LOGGER.error('no initial mission found')
