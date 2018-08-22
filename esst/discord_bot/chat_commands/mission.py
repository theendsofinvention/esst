# coding=utf-8
"""
Meh
"""
import pprint
import typing
from time import sleep

import emiz.edit_miz
import emiz.weather

from esst import commands, core, dcs, utils

LOGGER = core.MAIN_LOGGER.getChild(__name__)


def _mission_index_to_mission_name(mission_index):
    LOGGER.debug(f'converting mission index to mission name: {mission_index}')
    for index, mission_name in dcs.missions_manager.list_available_missions():
        if index == mission_index:
            LOGGER.debug(f'mission found: {mission_name}')
            return dcs.missions_manager.MissionPath(mission_name)
    LOGGER.debug('no mission found')
    return None


# pylint: disable=too-many-statements,too-many-branches,too-many-return-statements,too-many-arguments
def _load(name, icao, metar, time, max_wind, min_wind, force):  # noqa: C901
    if name is None:
        mission = dcs.missions_manager.get_running_mission()
        if not mission:
            LOGGER.error('unable to retrieve current mission')
            return
    else:
        try:
            LOGGER.debug(f'trying to cast mission name into an int: {name}')
            mission_number = int(name)
        except ValueError:
            LOGGER.debug(f'loading mission name: {name}')
            mission = dcs.missions_manager.MissionPath(name)
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
        error, metar = emiz.weather.custom_metar.CustomMetar.get_metar(metar)
        if error:
            LOGGER.error(error)
            return
    if icao:
        icao = icao.upper()
        LOGGER.info(f'obtaining METAR from: {icao}')
        error, metar_str = emiz.weather.noaa.retrieve_metar(icao)
        if error:
            LOGGER.error(error)
            return
        LOGGER.info(f'analyzing METAR string: {metar_str}')
        error, metar = emiz.weather.custom_metar.CustomMetar.get_metar(metar_str)
        if error:
            LOGGER.error(error)
            return

    if metar:
        info_metar = metar
        LOGGER.info(f'METAR: {metar.string()}')
    else:
        LOGGER.info('building METAR from mission file')
        # noinspection SpellCheckingInspection
        metar_str = emiz.weather.mizfile.get_metar_from_mission(str(mission.path), 'XXXX')
        error, info_metar = emiz.weather.custom_metar.CustomMetar.get_metar(metar_str)
        if error:
            LOGGER.error(error)
            return
        LOGGER.info(f'METAR: {info_metar.string()}')

    LOGGER.debug(f'editing "{mission.path}" to "{mission.auto.path}"')
    commands.DCS.block_start('loading mission')
    commands.DCS.kill(force=force)
    LOGGER.debug('waiting on DCS application to close')
    while core.Status.dcs_application != 'not running':
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
        error = emiz.edit_miz.edit_miz(**miz_edit_options)
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
        commands.DCS.unblock_start('loading mission')


@utils.arg(protected=True)
def delete(name: str):
    """
    Removes a mission file from the server
    """
    try:
        mission_number = int(name)
    except ValueError:
        mission = dcs.missions_manager.MissionPath(name)
        if not mission:
            LOGGER.error(f'mission file does not exist: {mission.path}')
            return
    else:
        mission = _mission_index_to_mission_name(mission_number)
        if not mission:
            LOGGER.error(
                f'invalid mission index: {mission_number}; use "!mission  show" to see available indices')
            return

    dcs.missions_manager.delete(mission)


# noinspection SpellCheckingInspection
@utils.arg('--force', help='force server restart even with connected players')
@utils.arg('--min-wind', help='minimum speed of the wind in MPS')
@utils.arg('--max-wind', help='maximum speed of the wind in MPS')
@utils.arg('-t', '--time',
           help='set the mission time (syntax: YYYYMMDDHHMMSS)\nExample: 2017/08/22 at 12:30:00 -> 20170822123000')
@utils.arg('-m', '--metar', nargs='+', metavar='METAR',
           help='update the weather from METAR string\nWARNING: METAR string may NOT contain dashes ("-")')
@utils.arg('-i', '--icao', help='update the weather from a given (real life) ICAO')
@utils.arg('-n', '--name',
           help='name or index of the mission to load (if not provided, will re-use the current mission)')
@utils.arg(protected=True)
# pylint: disable=too-many-arguments
def load(
        name: typing.Union[str, int] = None,
        icao: str = None,
        metar: str = None,
        time: str = None,
        max_wind: int = 40,
        min_wind: int = 0,
        force: bool = False,

):
    """
    Load a mission, allowing to set the weather or the time (protected).

    Missions can be loaded by typing their full name, or using the index number given by the "!mission show" command.
    """
    if not (force or commands.DCS.check_for_connected_players()):
        return
    if not any((name, icao, metar, time)):
        commands.DISCORD.say('Type "!mission load --help" to see available options')
        return
    core.CTX.loop.run_in_executor(None, _load, name, icao,
                                  metar, time, max_wind, min_wind, force)


def show():
    """
    Show list of missions available on the server
    """
    available_mission = '\n\t'.join(
        f'{n}. {m}' for n, m in dcs.missions_manager.list_available_missions())
    # available_mission = '\n\t'.join(available_mission)
    commands.DISCORD.say(
        'Available missions:\n'
        f'\t{available_mission}\n'
    )


def weather():
    """
    Displays the weather for the currently running mission
    """
    if core.Status.metar and core.Status.metar != 'unknown':
        error, metar = emiz.weather.custom_metar.CustomMetar.get_metar(core.Status.metar)
        if error:
            LOGGER.error(error)
            return

        commands.DISCORD.say(f'{metar.string()}')


def download():
    """
    Sends the currently running mission on Discord
    """
    mission = dcs.missions_manager.get_running_mission()
    if mission:
        commands.DISCORD.send_file(str(mission.path))


NAMESPACE = '!mission'
TITLE = 'Manage missions'
