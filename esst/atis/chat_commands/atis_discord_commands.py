# coding=utf-8
"""
ATIS Discord commands group
"""

from esst import core, utils

from .._atis_airfields import ALL_AIRFIELDS
from .._atis_get_info import get_info_for_icao
from .._univers_radio import URVoiceService

LOGGER = core.MAIN_LOGGER.getChild(__name__)


@utils.arg('icao', nargs=1)
def showfor(icao: list):
    """
    Show ATIS info for a specific airfield
    """
    icao_str = ''.join(icao).upper()
    try:
        info = get_info_for_icao(icao_str)
    except KeyError:
        LOGGER.error(f'ICAO not found in the list of currently active ATIS: {icao_str}')
        return
    running = 'running' if URVoiceService.is_running() else 'not running'
    info_str = f'UR voice service is {running}\n\n' \
               f'Metar: {core.Status.metar}\n' \
               f'Active runway: {info.active_runway}\n' \
               f'Information ID: {info.info_letter}\n' \
               f'ATIS speech: {core.CTX.atis_speech}'
    LOGGER.info(info_str)


def status():
    """
    Show UR voice service status
    """
    status_ = 'running' if URVoiceService.is_running() else 'not running'
    LOGGER.info(f'UniversRadio voice service is {status_}')


def show():
    """
    Shows ICAO & frequencies for the ATIS
    """
    output = ['List of ATIS frequencies:']
    for airfield in ALL_AIRFIELDS:
        output.append(f'{airfield.icao} {airfield.name}: {airfield.atis_freq.long_freq()}')
    LOGGER.info('\n'.join(output))


NAMESPACE = '!atis'
TITLE = 'Manage ATIS service'
