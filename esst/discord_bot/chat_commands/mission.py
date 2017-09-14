# coding=utf-8
# pylint: disable=bad-whitespace,missing-docstring
"""
Meh
"""
from time import sleep

from emiz import build_metar_from_mission, edit_miz, parse_metar_string, retrieve_metar

from esst.commands import DCS, DISCORD
from esst.core import CTX, MAIN_LOGGER, Status
from esst.dcs import missions_manager

from .arg import arg

LOGGER = MAIN_LOGGER.getChild(__name__)


def _load(name, icao, metar, time, max_wind, min_wind, force):  # noqa: C901  # pylint: disable=too-many-statements
    if name is None:
        mission = missions_manager.get_running_mission().strip_suffix()
    else:
        mission = missions_manager.MissionPath(name)

    if not mission:
        LOGGER.error(f'mission file does not exist: {mission.path}')
        return

    if metar:
        metar = ' '.join(metar)
        LOGGER.info(f'analyzing METAR string: {metar}')
        error, metar = parse_metar_string(metar)
        if error:
            LOGGER.error(error)
            return
        DISCORD.say(f'{metar.string()}')
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
        DISCORD.say(f'{metar.string()}')

    if metar:
        info_metar = metar
    else:
        LOGGER.info('building METAR from mission file')
        metar_str = build_metar_from_mission(mission.path, 'XXXX')
        error, info_metar = parse_metar_string(metar_str)
        if error:
            LOGGER.error(error)
            return
        LOGGER.info(f'{info_metar.string()}')

    LOGGER.debug(f'editing "{mission.path}" to "{mission.rlwx.path}"')
    DCS.cannot_start()
    DCS.kill(force=force)
    while Status.dcs_application != 'not running':
        sleep(1)
    edit_str = []
    if time:
        edit_str.append('time')
    if metar:
        edit_str.append('weather')
    if edit_str:
        edit_str = ' and '.join(edit_str)
        LOGGER.info(f'loading {mission.name} with {edit_str} (this may take a few seconds)')
    else:
        LOGGER.info(f'loading {mission.name}')
    try:
        error = edit_miz(mission.path, mission.rlwx.path, metar, time, min_wind, max_wind)
        if error:
            LOGGER.error(error)
        else:
            LOGGER.debug('mission has been successfully edited')
            mission.rlwx.set_as_active(info_metar.code)
    finally:
        DCS.can_start()


@arg('-m', '--metar', nargs='+', metavar='METAR')
@arg(protected=True)
def load(
        name: 'name of the mission to load (if not provided, will re-use the current mission)' = None,
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
    Load a mission, allowing to set the weather or the time (protected)
    """
    if not (force or DCS.check_for_connected_players()):
        return
    if not any((name, icao, metar, time)):
        DISCORD.say('Type "!mission load --help" to see available options')
        return
    CTX.loop.run_in_executor(None, _load, name, icao, metar, time, max_wind, min_wind, force)


def show():
    """
    Show list of missions available on the server
    """

    available_mission = '\n\t'.join(missions_manager.list_available_missions())
    DISCORD.say(
        'Available missions:\n'
        f'\t{available_mission}\n'
    )


def weather():
    """
    Displays the weather for the currently running mission
    """
    mission = missions_manager.get_running_mission()
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
        DISCORD.send(mission.path)


NAMESPACE = '!mission'
TITLE = 'Manage missions'
