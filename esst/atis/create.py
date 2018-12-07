# coding=utf-8
"""
Generates ATIS from METAR
"""

import queue
import re
import threading
import typing
from pathlib import Path

import elib_wx

from esst import ATISConfig, LOGGER, core
from ._atis_airfields import ALL_AIRFIELDS
from ._atis_identifier import get_random_identifier
from ._atis_objects import ATISForAirfield
from ._atis_status import Status
from ._univers_radio import Airfield, URVoiceService, URVoiceServiceSettings
from . import tts

RE_CLOUD_COVER = re.compile(r'(SKC|FEW|BKN|OVC|NSC)[\d]{3}\. ')


def _cleanup_full_speech(full_speech: str) -> str:
    match = RE_CLOUD_COVER.search(full_speech)
    if match:
        full_speech = RE_CLOUD_COVER.sub('', full_speech)

    return full_speech


def _build_speech_for_airfield(
        airfield: Airfield,
        wind_dir: int,
        speech_atis: str,
        ur_settings: URVoiceServiceSettings,
        atis_queue: queue.Queue,
):
    LOGGER.debug('%s: processing', airfield.icao)
    atis_file = Path(f'atis/{airfield.icao}.mp3').absolute()
    LOGGER.debug('%s: ATIS file path: %s', airfield.icao, atis_file)
    active_runway = airfield.get_active_runway(wind_dir)
    LOGGER.debug('%s: active runway: %s', airfield.icao, active_runway.long_name())
    speech_intro = f'ATIS for {airfield.name}'
    LOGGER.debug('%s: ATIS intro: %s', airfield.icao, speech_intro)
    speech_active_runway = f'Active runway {active_runway.long_name()}'
    LOGGER.debug('%s: active runway speech: %s', airfield.icao, speech_active_runway)
    information_identifier, information_letter = get_random_identifier()
    speech_information = f'Advise you have information, {information_identifier}, on first contact.'
    LOGGER.debug('%s: speech information: %s', airfield.icao, speech_information)
    full_speech = '. '.join([speech_intro, speech_atis, speech_active_runway, speech_information])
    full_speech = _cleanup_full_speech(full_speech)
    LOGGER.debug('%s: full speech: %s', airfield.icao, full_speech)
    LOGGER.debug('%s: writing MP3 file for: %s', airfield.icao, airfield.icao)
    tts.text_to_speech(full_speech, atis_file, True)
    ur_settings.add_station(airfield)
    atis_queue.put(ATISForAirfield(airfield.icao, active_runway, information_identifier, information_letter))


def _update_status(atis_queue: queue.Queue):
    Status.active_atis = {}
    while True:
        try:
            atis_for_airfield = atis_queue.get(block=False)
        except queue.Empty:
            break
        Status.active_atis[atis_for_airfield.icao] = atis_for_airfield


def _parse_metar_string(metar_str: str) -> typing.Optional[elib_wx.Weather]:
    LOGGER.debug('parsing METAR string')
    # noinspection SpellCheckingInspection
    return elib_wx.Weather(metar_str)


def generate_atis(
        weather: elib_wx.Weather,
        include_icao: typing.List[str] = None,
        exclude_icao: typing.List[str] = None
):
    """
    Create MP3 from METAR
    """
    if not ATISConfig.ATIS_CREATE():
        LOGGER.info('skipping ATIS creation as per config')
        return
    atis_dir = Path('atis').absolute()
    if not atis_dir.exists():
        LOGGER.info('creating ATIS dir: %s', atis_dir)
        atis_dir.mkdir()
    URVoiceService.kill()

    LOGGER.info('creating ATIS from METAR: %s', weather.raw_metar_str)

    wind_dir = int(weather.wind_direction.value())
    LOGGER.debug('wind direction: %s', wind_dir)

    speech_atis = weather.as_speech()
    core.CTX.atis_speech = speech_atis
    LOGGER.debug('ATIS speech: %s', speech_atis)

    ur_settings = URVoiceServiceSettings()

    if include_icao:
        include_icao = [icao.upper() for icao in include_icao]

    if exclude_icao:
        exclude_icao = [icao.upper() for icao in exclude_icao]

    threads = []
    atis_queue: queue.Queue = queue.Queue()
    for airfield in ALL_AIRFIELDS:
        if core.CTX.exit:
            break
        if include_icao and airfield.icao.upper() not in include_icao:
            LOGGER.debug('%s: skipping (not included)', airfield.icao)
            continue
        if exclude_icao and airfield.icao.upper() in exclude_icao:
            LOGGER.debug('%s: skipping (excluded)', airfield.icao)
            continue

        thread = threading.Thread(
            target=_build_speech_for_airfield,
            args=(airfield, wind_dir, speech_atis, ur_settings, atis_queue)
        )
        threads.append(thread)
        thread.start()
    for job in threads:
        job.join()

    _update_status(atis_queue)

    list_of_active_icao = ', '.join(list(Status.active_atis.keys()))
    LOGGER.debug('generated %s ATIS for: %s)', len(Status.active_atis), list_of_active_icao)

    LOGGER.debug('writing UR settings')
    ur_settings.write_settings_file()
    URVoiceService.start_service()
