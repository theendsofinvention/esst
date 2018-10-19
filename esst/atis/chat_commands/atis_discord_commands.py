# coding=utf-8
"""
ATIS Discord commands group
"""

from esst import LOGGER, core, utils
from .._atis_airfields import ALL_AIRFIELDS
from .._atis_get_info import get_info_for_icao
from .._univers_radio import URVoiceService


# noinspection SpellCheckingInspection
@utils.arg('icao', nargs=1)
def showfor(icao: list):
    """
    Show ATIS info for a specific airfield
    """
    icao_str = ''.join(icao).upper()
    try:
        info = get_info_for_icao(icao_str)
    except KeyError:
        LOGGER.error('ICAO not found in the list of currently active ATIS:  %s', icao_str)
        return
    if core.Status.metar == 'unknown':
        LOGGER.error('no weather information available at this time')
        return
    running = 'running' if URVoiceService.is_running() else 'not running'
    # type: ignore
    _weather = core.Status.metar.as_str()  # pylint: disable=no-member
    # type: ignore
    _metar = core.Status.metar.raw_metar_str  # pylint: disable=no-member
    info_str = f'UR voice service is {running}\n\n' \
               f'METAR:\n{_metar}\n\n' \
               f'Weather:\n{_weather}\n\n' \
               f'Active runway: {info.active_runway}\n' \
               f'Information ID: {info.info_letter}\n' \
               f'ATIS speech: {core.CTX.atis_speech}'
    LOGGER.info(info_str)


def status():
    """
    Show UR voice service status
    """
    status_ = 'running' if URVoiceService.is_running() else 'not running'
    LOGGER.info('UniversRadio voice service is  %s', status_)


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
