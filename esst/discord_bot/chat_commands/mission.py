# coding=utf-8

from argh import arg

from esst.core import MAIN_LOGGER, Status, CTX
from esst.commands import DCS, DISCORD
from esst.dcs import missions_manager
from emiz import edit_miz, parse_metar_string, retrieve_metar, build_metar_from_mission


LOGGER = MAIN_LOGGER.getChild(__name__)


def _load(name, icao, metar, time, max_wind, min_wind):
    if name is None:
        mission = missions_manager.get_running_mission().strip_suffix()
    else:
        mission = missions_manager.MissionPath(name)

    if not mission:
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
    error = edit_miz(mission.path, mission.rlwx.path, metar, time, min_wind, max_wind)
    if error:
        LOGGER.error(error)
    else:
        LOGGER.debug('mission has been successfully edited')
        mission.rlwx.set_as_active(info_metar.code)
        DCS.restart()


@arg('-m', '--metar', nargs='+', metavar='METAR')
def load(
        name: 'name of the mission to load' = None,
        icao: 'update the weather from ICAO' = None,
        metar: 'update the weather from METAR string\n'
               'WARNING: METAR string may NOT contain dashes ("-")' = None,
        time: 'set the mission time (syntax: YYYYMMDDHHMMSS)\n'
              'Ex: 2017/08/22 at 12:30:00 -> 20170822123000' = None,
        max_wind: 'maximum speed of the wind in MPS' = 40,
        min_wind: 'minimum speed of the wind in MPS' = 0,

):
    """
    Load a mission, allowing to set the weather or the time
    """
    CTX.loop.run_in_executor(None, _load, name, icao, metar, time, max_wind, min_wind)


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


namespace = '!mission'
title = 'Manage missions'
