# coding=utf-8
"""
Meh
"""
import pprint
import typing
from time import sleep

import emiz.edit_miz
import emiz.weather

from esst import LOGGER, commands, core, utils
from esst.dcs import missions_manager


def _mission_index_to_mission_name(mission_index):
    LOGGER.debug('converting mission index to mission name: %s', mission_index)
    for index, mission_name in missions_manager.list_available_missions():
        if index == mission_index:
            LOGGER.debug('mission found: %s', mission_name)
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
    else:
        try:
            LOGGER.debug('trying to cast mission name into an int: %s', name)
            mission_number = int(name)
        except ValueError:
            LOGGER.debug('loading mission name: %s', name)
            mission = missions_manager.MissionPath(name)
            if not mission:
                LOGGER.debug('mission path not found: %s', mission.path)
                LOGGER.error('mission file not found: %s', mission.name)
                return
        else:
            LOGGER.debug('loading mission number: %s', mission_number)
            mission = _mission_index_to_mission_name(mission_number)
            if not mission:
                LOGGER.error('invalid mission index: %s; use "!mission  show" to see available indices', mission_number)
                return

    LOGGER.info('loading mission file: %s', mission.path)
    if metar:
        metar = ' '.join(metar)
        LOGGER.info('analyzing METAR string: %s', metar)
        error, metar = emiz.weather.custom_metar.CustomMetar.get_metar(metar)
        if error:
            LOGGER.error(error)
            return
    if icao:
        icao = icao.upper()
        LOGGER.info('obtaining METAR from: %s', icao)
        error, metar_str = emiz.weather.noaa.retrieve_metar(icao)
        if error:
            LOGGER.error(error)
            return
        LOGGER.info('analyzing METAR string: %s', metar_str)
        error, metar = emiz.weather.custom_metar.CustomMetar.get_metar(metar_str)
        if error:
            LOGGER.error(error)
            return

    if metar:
        info_metar = metar
        LOGGER.info('METAR: %s', metar.string())
    else:
        LOGGER.info('building METAR from mission file')
        # noinspection SpellCheckingInspection
        metar_str = emiz.weather.mizfile.get_metar_from_mission(str(mission.path), 'XXXX')
        error, info_metar = emiz.weather.custom_metar.CustomMetar.get_metar(metar_str)
        if error:
            LOGGER.error(error)
            return
        LOGGER.info('METAR: %s', info_metar.string())

    LOGGER.debug('editing "%s" to "%s"', mission.path, mission.auto.path)
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
        LOGGER.info('loading %s with %s (this may take a few seconds)', mission.name, edit_str)
    else:
        LOGGER.info('loading %s as is (no edit)', mission.name)
    try:
        miz_edit_options = dict(infile=str(mission.path), outfile=str(mission.auto.path), metar=metar, time=time,
                                min_wind=min_wind, max_wind=max_wind)
        LOGGER.debug('editing miz file with options:\n%s', pprint.pformat(miz_edit_options))
        error = emiz.edit_miz.edit_miz(**miz_edit_options)
        if error:
            if error == 'nothing to do!':
                LOGGER.debug('loading mission "as is": %s', mission.path)
                mission.set_as_active(info_metar.code)
            else:
                LOGGER.error(error)
        else:
            LOGGER.debug('mission has been successfully edited, setting as active: %s', mission.auto.path)
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
        mission = missions_manager.MissionPath(name)
        if not mission:
            LOGGER.error('mission file does not exist: %s', mission.path)
            return
    else:
        mission = _mission_index_to_mission_name(mission_number)
        if not mission:
            LOGGER.error('invalid mission index: %s; use "!mission show" to see available indices',
                         mission_number
                         )
            return

    missions_manager.delete(mission)


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
        f'{n}. {m}' for n, m in missions_manager.list_available_missions())
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
    mission = missions_manager.get_running_mission()
    if mission:
        commands.DISCORD.send_file(str(mission.path))


NAMESPACE = '!mission'
TITLE = 'Manage missions'
