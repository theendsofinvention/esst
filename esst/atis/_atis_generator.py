# coding=utf-8
"""
Generates ATIS from METAR
"""

import typing
from pathlib import Path

import elib.tts
import emiz.weather
from esst import core

from ._atis_airfields import ALL_AIRFIELDS
from ._atis_identifier import get_random_identifier
from ._atis_objects import ATISForAirfield
from ._atis_status import Status
from ._univers_radio import URVoiceService, URVoiceServiceSettings

LOGGER = core.MAIN_LOGGER.getChild(__name__)


def _build_speech_for_airfield(airfield, wind_dir, speech_atis, ur_settings) -> ATISForAirfield:
    LOGGER.debug(f'processing airfield: {airfield.icao}')
    atis_file = Path(f'{airfield.icao}.mp3').absolute()
    LOGGER.debug(f'ATIS file path: {atis_file}')
    active_runway = airfield.get_active_runway(wind_dir)
    LOGGER.debug(f'active runway: {active_runway.long_name()}')
    speech_intro = f'ATIS for {airfield.name}'
    LOGGER.debug(f'ATIS intro: {speech_intro}')
    speech_active_runway = f'Active runway {active_runway.long_name()}'
    LOGGER.debug(f'active runway speech: {speech_active_runway}')
    information_identifier, information_letter = get_random_identifier()
    speech_information = f'Advise you have information, {information_identifier}, on first contact.'
    LOGGER.debug(f'speech information: {speech_information}')
    full_speech = '. '.join([speech_intro, speech_atis, speech_active_runway, speech_information])
    LOGGER.debug(f'full speech: {full_speech}')
    LOGGER.debug(f'writing MP3 file for: {airfield.icao}')
    elib.tts.text_to_speech(full_speech, Path(atis_file), True)
    ur_settings.add_station(airfield)
    return ATISForAirfield(airfield.icao, active_runway, information_identifier, information_letter)


def generate_atis(metar_str: str,
                  include_icao: typing.List[str] = None,
                  exclude_icao: typing.List[str] = None):
    """
    Create MP3 from METAR
    """
    if not core.CFG.atis_create:
        LOGGER.info('skipping ATIS creation as per config')
        return
    URVoiceService.kill()
    LOGGER.info(f'creating ATIS from METAR: {metar_str}')
    LOGGER.debug('parsing METAR string')
    # noinspection SpellCheckingInspection
    metar_str = metar_str.replace('XXXX', 'UGTB')
    error, metar = emiz.weather.custom_metar.CustomMetar.get_metar(metar_str)
    if error:
        LOGGER.error('failed to parse METAR')
        raise RuntimeError(metar)
    wind_dir = metar.wind_dir.value()
    LOGGER.debug(f'wind direction: {wind_dir}')
    speech_atis = emiz.weather.AVWX.metar_to_speech(metar_str)
    core.CTX.atis_speech = speech_atis
    LOGGER.debug(f'ATIS speech: {speech_atis}')

    ur_settings = URVoiceServiceSettings()
    active_atis = {}

    if include_icao:
        include_icao = [icao.upper() for icao in include_icao]

    if exclude_icao:
        exclude_icao = [icao.upper() for icao in exclude_icao]

    for airfield in ALL_AIRFIELDS:
        if core.CTX.exit:
            break
        if include_icao and airfield.icao.upper() not in include_icao:
            LOGGER(f'skipping not included ICAO: {airfield.icao}')
            continue
        if exclude_icao and airfield.icao.upper() in exclude_icao:
            LOGGER(f'skipping excluded ICAO: {airfield.icao}')
            continue
        active_atis[airfield.icao] = _build_speech_for_airfield(airfield, wind_dir, speech_atis, ur_settings)

    list_of_active_icao = ', '.join(active_atis.keys())
    LOGGER.debug(f'generated {len(active_atis)} ATIS for: {list_of_active_icao})')
    Status.active_atis = active_atis

    LOGGER.debug('writing UR settings')
    ur_settings.write_settings_file()
    URVoiceService.start_service()
