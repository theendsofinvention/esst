# coding=utf-8
"""
Generates ATIS from METAR
"""

import queue
import re
import threading
import typing
from pathlib import Path

import elib.tts
import emiz.weather

from esst import core
from ._atis_airfields import ALL_AIRFIELDS
from ._atis_identifier import get_random_identifier
from ._atis_objects import ATISForAirfield
from ._atis_status import Status
from ._univers_radio import Airfield, URVoiceService, URVoiceServiceSettings

LOGGER = core.MAIN_LOGGER.getChild(__name__)

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
    LOGGER.debug(f'{airfield.icao}: processing')
    atis_file = Path(f'atis/{airfield.icao}.mp3').absolute()
    LOGGER.debug(f'{airfield.icao}: ATIS file path: {atis_file}')
    active_runway = airfield.get_active_runway(wind_dir)
    LOGGER.debug(f'{airfield.icao}: active runway: {active_runway.long_name()}')
    speech_intro = f'ATIS for {airfield.name}'
    LOGGER.debug(f'{airfield.icao}: ATIS intro: {speech_intro}')
    speech_active_runway = f'Active runway {active_runway.long_name()}'
    LOGGER.debug(f'{airfield.icao}: active runway speech: {speech_active_runway}')
    information_identifier, information_letter = get_random_identifier()
    speech_information = f'Advise you have information, {information_identifier}, on first contact.'
    LOGGER.debug(f'{airfield.icao}: speech information: {speech_information}')
    full_speech = '. '.join([speech_intro, speech_atis, speech_active_runway, speech_information])
    full_speech = _cleanup_full_speech(full_speech)
    LOGGER.debug(f'{airfield.icao}: full speech: {full_speech}')
    LOGGER.debug(f'{airfield.icao}: writing MP3 file for: {airfield.icao}')
    elib.tts.text_to_speech(full_speech, atis_file, True)
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


def _parse_metar_string(metar_str: str) -> emiz.weather.custom_metar.CustomMetar:
    LOGGER.debug('parsing METAR string')
    # noinspection SpellCheckingInspection
    metar_str = metar_str.replace('XXXX', 'UGTB')
    error, metar = emiz.weather.custom_metar.CustomMetar.get_metar(metar_str)
    if error:
        LOGGER.error('failed to parse METAR')
        raise RuntimeError(metar)

    return metar


def generate_atis(
        metar_str: str,
        include_icao: typing.List[str] = None,
        exclude_icao: typing.List[str] = None
):
    """
    Create MP3 from METAR
    """
    if not core.CFG.atis_create:
        LOGGER.info('skipping ATIS creation as per config')
        return
    atis_dir = Path('atis').absolute()
    if not atis_dir.exists():
        LOGGER.info('creating ATIS dir: %s', atis_dir)
        atis_dir.mkdir()
    URVoiceService.kill()

    LOGGER.info(f'creating ATIS from METAR: {metar_str}')
    metar = _parse_metar_string(metar_str)

    wind_dir = int(metar.wind_dir.value())
    LOGGER.debug(f'wind direction: {wind_dir}')

    speech_atis = emiz.weather.AVWX.metar_to_speech(metar_str)
    core.CTX.atis_speech = speech_atis
    LOGGER.debug(f'ATIS speech: {speech_atis}')

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
            LOGGER(f'{airfield.icao}: skipping (not included)')
            continue
        if exclude_icao and airfield.icao.upper() in exclude_icao:
            LOGGER(f'{airfield.icao}: skipping (excluded)')
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
    LOGGER.debug(f'generated {len(Status.active_atis)} ATIS for: {list_of_active_icao})')

    LOGGER.debug('writing UR settings')
    ur_settings.write_settings_file()
    URVoiceService.start_service()
