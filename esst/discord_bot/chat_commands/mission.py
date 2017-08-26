# coding=utf-8

from esst.core import MAIN_LOGGER, Status
from esst.commands import DCS, DISCORD
from esst.dcs import missions_manager


LOGGER = MAIN_LOGGER.getChild(__name__)


def load(mission_name: 'mission to load' = None,):
    """
    Show ESST version
    """
    if mission_name is None:
        mission_file = missions_manager.get_running_mission()
    else:
        mission_file = missions_manager.get_path_from_name(mission_name)
    if not mission_file:
        return

    if mission_file:
        DISCORD.say(mission_file)


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
