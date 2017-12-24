# coding=utf-8
# pylint: disable=bad-whitespace,missing-docstring
"""
Meh
"""
import pprint
from time import sleep

from emiz import build_metar_from_mission, edit_miz, parse_metar_string, retrieve_metar

from esst.commands import DCS, DISCORD
from esst.core import CTX, MAIN_LOGGER, Status
from esst.dcs import missions_manager

from .arg import arg

LOGGER = MAIN_LOGGER.getChild(__name__)


def _mission_index_to_mission_name(mission_index):
    LOGGER.debug(f'converting mission index to mission name: {mission_index}')
    for index, mission_name in missions_manager.list_available_missions():
        if index == mission_index:
            LOGGER.debug(f'mission found: {mission_name}')
            return missions_manager.MissionPath(mission_name)
    LOGGER.debug('no mission found')
    return None


# pylint: disable=too-many-statements,too-many-branches,too-many-return-statements,too-many-arguments
def _load(name, icao, metar, time, max_wind, min_wind, force):  # noqa: C901
    if name is None:
        mission = missions_manager.get_running_mission()
        if not mission:
            LOGGER.error('unable to retrieve current mission')
            return
        mission = mission.name
    else:
        try:
            LOGGER.debug(f'trying to cast mission name into an int: {name}')
            mission_number = int(name)
        except ValueError:
            LOGGER.debug(f'loading mission name: {name}')
            mission = missions_manager.MissionPath(name)
            if not mission:
                LOGGER.debug(f'mission path not found: {mission.path}')
                LOGGER.error(f'mission file not found: {mission.name}')
                return
        else:
            LOGGER.debug(f'loading mission number: {mission_number}')
            mission = _mission_index_to_mission_name(mission_number)
            if not mission:
                LOGGER.error(f'invalid mission index: {mission_number}; use "!mission  show" to see available indices')
                return

    LOGGER.info(f'loading mission file: {mission.path}')
    if metar:
        metar = ' '.join(metar)
        LOGGER.info(f'analyzing METAR string: {metar}')
        error, metar = parse_metar_string(metar)
        if error:
            LOGGER.error(error)
            return
    if icao:
        icao = icao.upper()
        LOGGER.info(f'obtaining METAR from: {icao}')
        error, metar_str = retrieve_metar(icao)
        if error:
            LOGGER.error(error)
            return
        LOGGER.info(f'analyzing METAR string: {metar_str}')
        error, metar = parse_metar_string(metar_str)
        if error:
            LOGGER.error(error)
            return

    if metar:
        info_metar = metar
        LOGGER.info(f'METAR: {metar.string()}')
    else:
        LOGGER.info('building METAR from mission file')
        metar_str = build_metar_from_mission(str(mission.path), 'XXXX')
        error, info_metar = parse_metar_string(metar_str)
        if error:
            LOGGER.error(error)
            return
        LOGGER.info(f'METAR: {info_metar.string()}')

    LOGGER.debug(f'editing "{mission.path}" to "{mission.auto.path}"')
    DCS.cannot_start()
    DCS.kill(force=force)
    LOGGER.debug('waiting on DCS application to close')
    while Status.dcs_application != 'not running':
        sleep(1)
    LOGGER.debug('DCS has closed, carrying on')
    edit_str = []
    if time:
        edit_str.append('time')
    if metar:
        edit_str.append('weather')
    if edit_str:
        edit_str = ' and '.join(edit_str)
        LOGGER.info(
            f'loading {mission.name} with {edit_str} (this may take a few seconds)')
    else:
        LOGGER.info(f'loading {mission.name} as is (no edit)')
    try:
        miz_edit_options = dict(infile=str(mission.path), outfile=str(mission.auto.path), metar=metar, time=time,
                                min_wind=min_wind, max_wind=max_wind)
        LOGGER.debug(f'editing miz file with options:\n{pprint.pformat(miz_edit_options)}')
        error = edit_miz(**miz_edit_options)
        if error:
            if error == 'nothing to do!':
                LOGGER.debug(f'loading mission "as is": {mission.path}')
                mission.set_as_active(info_metar.code)
            else:
                LOGGER.error(error)
        else:
            LOGGER.debug(f'mission has been successfully edited, setting as active: {mission.auto.path}')
            mission.auto.set_as_active(info_metar.code)
    finally:
        DCS.can_start()


@arg(protected=True)
def delete(name: 'name or index of the mission to load'):
    """
    Removes a mission file from the server (protected)
    """
    try:
        mission_number = int(name)
    except ValueError:
        mission = missions_manager.MissionPath(name)
        if not mission:
            LOGGER.error(f'mission file does not exist: {mission.path}')
            return
    else:
        mission = _mission_index_to_mission_name(mission_number)
        if not mission:
            LOGGER.error(
                f'invalid mission index: {mission_number}; use "!mission  show" to see available indices')
            return

    missions_manager.delete(mission)


@arg('-m', '--metar', nargs='+', metavar='METAR')
@arg(protected=True)
# pylint: disable=too-many-arguments
def load(
        name: 'name or index of the mission to load (if not provided, will re-use the current mission)' = None,
        icao: 'update the weather from ICAO' = None,
        metar: 'update the weather from METAR string\n'
               'WARNING: METAR string may NOT contain dashes ("-")' = None,
        time: 'set the mission time (syntax: YYYYMMDDHHMMSS)\n'
              'Ex: 2017/08/22 at 12:30:00 -> 20170822123000' = None,
        max_wind: 'maximum speed of the wind in MPS' = 40,
        min_wind: 'minimum speed of the wind in MPS' = 0,
        force: 'force server restart even with connected players' = False,

):
    """
    Load a mission, allowing to set the weather or the time (protected).

    Missions can be loaded by typing their full name, or using the index number given by the "!mission show" command.
    """
    if not (force or DCS.check_for_connected_players()):
        return
    if not any((name, icao, metar, time)):
        DISCORD.say('Type "!mission load --help" to see available options')
        return
    CTX.loop.run_in_executor(None, _load, name, icao,
                             metar, time, max_wind, min_wind, force)


def show():
    """
    Show list of missions available on the server
    """
    available_mission = '\n\t'.join(
        f'{n}. {m}' for n, m in missions_manager.list_available_missions())
    # available_mission = '\n\t'.join(available_mission)
    DISCORD.say(
        'Available missions:\n'
        f'\t{available_mission}\n'
    )


def weather():
    """
    Displays the weather for the currently running mission
    """
    mission = missions_manager.get_running_mission()
    if not mission:
        return
    if mission and Status.metar and Status.metar != 'unknown':
        error, metar = parse_metar_string(Status.metar)
        if error:
            LOGGER.error(error)
            return
        else:
            DISCORD.say(f'Weather for {mission.name}:\n{metar.string()}')


def download():
    """
    Sends the currently running mission on Discord
    """
    mission = missions_manager.get_running_mission()
    if mission:
        DISCORD.send(str(mission.path))


NAMESPACE = '!mission'
TITLE = 'Manage missions'
