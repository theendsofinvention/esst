# coding=utf-8
"""
Meh
"""
import typing
from time import sleep

import elib_miz
import elib_wx

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
def _load(name, metar_or_icao, time, max_wind, min_wind, force):  # noqa: C901
    if max_wind or min_wind:
        LOGGER.warning('"min_wind" and "max_wind" have been disabled for the time being')
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
    if time:
        try:
            mission_time = elib_miz.MissionTime.from_string(time)
            LOGGER.info('setting mission time: %s', mission_time.iso_format)
        except elib_miz.exc.InvalidDateTimeString:
            LOGGER.error('invalid date-time string: %s', time)
            return
        except ValueError as err:
            LOGGER.error(err)
            return
    else:
        mission_time = None
    if metar_or_icao:
        LOGGER.info('analyzing METAR string: %s', metar_or_icao)
        try:
            weather_ = elib_wx.Weather(metar_or_icao)
            LOGGER.info('setting mission weather: %s', weather_.as_str())
        except elib_wx.BadStationError:
            LOGGER.error('wrong ICAO code: %s', metar_or_icao)
            return
        LOGGER.info('METAR: %s', weather_.raw_metar_str)
    else:
        LOGGER.info('building METAR from mission file')
        # noinspection SpellCheckingInspection
        weather_ = elib_wx.Weather(str(mission.path))
        LOGGER.info('METAR: %s', weather_.as_str())

    commands.DCS.block_start('loading mission')
    commands.DCS.kill(force=force)
    try:
        LOGGER.debug('waiting on DCS application to close')
        while core.Status.dcs_application != 'not running':
            sleep(1)
        LOGGER.debug('DCS has closed, carrying on')
        active_mission = mission
        if time:
            mission_time.apply_to_miz(str(mission.path), str(mission.auto.path), overwrite=True)
            active_mission = mission.auto
        if metar_or_icao:
            weather_.apply_to_miz(str(mission.path), str(mission.auto.path), overwrite=True)
            active_mission = mission.auto
        active_mission.set_as_active(weather_)
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
@utils.arg('--min-wind', help='minimum speed of the wind in KTS')
@utils.arg('--max-wind', help='maximum speed of the wind in KTS')
@utils.arg('-t', '--time',
           help='set the mission time (syntax: YYYYMMDDHHMMSS)\nExample: 2017/08/22 at 12:30:00 -> 20170822123000')
@utils.arg('-wx', '--metar-or-icao', help='update the weather from a given (real life) ICAO or a plain (valid) '
                                          'METAR string\n'
                                          'WARNING: loading from a METAR string does not currently work')
@utils.arg('-n', '--name',
           help='name or index of the mission to load (if not provided, will re-use the current mission)')
@utils.arg(protected=True)
# pylint: disable=too-many-arguments
def load(
        name: typing.Union[str, int] = None,
        metar_or_icao: str = None,
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
    if not any((name, metar_or_icao, time)):
        commands.DISCORD.say('Type "!mission load --help" to see available options')
        return
    core.CTX.loop.run_in_executor(None, _load, name, metar_or_icao, time, max_wind, min_wind, force)


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


@utils.arg('--dcs', help='shows the weather in raw DCS format')
def weather(dcs: bool = False):
    """
    Displays the weather for the currently running mission
    """
    if core.Status.metar and core.Status.metar != 'unknown':
        if dcs:
            _weather = core.Status.metar.generate_dcs_weather().__repr__()  # pylint: disable=no-member
        else:
            _weather = core.Status.metar.as_str()  # pylint: disable=no-member
        commands.DISCORD.say(_weather)
    else:
        commands.DISCORD.say('There is currently no METAR information')


def download():
    """
    Sends the currently running mission on Discord
    """
    mission = missions_manager.get_running_mission()
    if mission:
        commands.DISCORD.send_file(str(mission.path))


NAMESPACE = '!mission'
TITLE = 'Manage missions'
