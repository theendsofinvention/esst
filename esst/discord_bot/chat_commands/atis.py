# coding=utf-8
"""
ATIS Discord commands group
"""

from esst.atis.atis import ATIS
from esst.atis.univers_radio.airfields import ALL_AIRFIELDS
from esst.atis.univers_radio.ur_voice_service import URVoiceService
from esst.commands import DISCORD
from esst.core import MAIN_LOGGER, Status
from esst.discord_bot.chat_commands.arg import arg

LOGGER = MAIN_LOGGER.getChild(__name__)


@arg('icao', nargs=1)
def show(icao: list):
    """
    Show ATIS info for a specific airfield
    """
    icao = ''.join(icao).upper()
    try:
        info = ATIS.get_info_for_icao(icao)
    except KeyError:
        LOGGER.error(f'ICAO not found in the list of currently active ATIS: {icao}')
        return
    running = 'running' if URVoiceService.is_running() else 'not running'
    info_str = f'UR voice service is {running}\n\n' \
               f'Metar: {Status.metar}\n' \
               f'Active runway: {info.active_runway}\n' \
               f'Information ID: {info.info_id}'
    DISCORD.say(info_str)


def status():
    """
    Show UR voice service status
    """
    status_ = 'running' if URVoiceService.is_running() else 'not running'
    DISCORD.say(f'UniversRadio voice service is {status_}')


def frequencies():
    """
    Shows frequencies for the ATIS in Georgia
    """
    output = ['List of ATIS frequencies in Georgia:']
    for airfield in ALL_AIRFIELDS:
        output.append(f'{airfield.name}: {airfield.atis_freq.long_freq()}')
    DISCORD.say('\n'.join(output))


NAMESPACE = '!atis'
TITLE = 'Manage ATIS service'
