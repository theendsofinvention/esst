# coding=utf-8

from argh import arg

from emiz.weather import retrieve_metar, set_weather_from_metar_str, set_weather_from_icao, build_metar_from_mission, parse_metar_string
from esst.core import MAIN_LOGGER, Status, CTX
from esst.commands import DCS, DISCORD
from esst.dcs import missions_manager


LOGGER = MAIN_LOGGER.getChild(__name__)


def _load(name, icao, metar):
    if name is None:
        mission = missions_manager.get_running_mission()
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
        LOGGER.info(f'{metar.string()}')
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
        LOGGER.info(f'{metar.string()}')

    if metar:
        error, success = set_weather_from_metar_str(metar.code, mission.path, mission.rlwx.path)
        if error:
            LOGGER.error(error)
            return
        else:
            LOGGER.info(success)
        active_mission = mission.rlwx
    else:
        LOGGER.info('building METAR from mission file')
        metar_str = build_metar_from_mission(mission.path, 'XXXX')
        error, metar = parse_metar_string(metar_str)
        if error:
            LOGGER.error(error)
            return
        LOGGER.info(f'{metar.string()}')
        active_mission = mission

    active_mission.set_as_active(metar.code)
    DCS.restart()


@arg('-m', '--metar', nargs='+', metavar='METAR')
def load(
        name: 'name of the mission to load' = None,
        icao: 'update the weather from ICAO' = None,
        metar: 'update the weather from METAR string' = None,
):
    """
    Load a mission, allowing to set the weather or the time
    """
    CTX.loop.run_in_executor(None, _load, name, icao, metar)


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
