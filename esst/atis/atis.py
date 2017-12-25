# coding=utf-8
"""
Manages ATIS services
"""

from pathlib import Path

from elib.tts import text_to_speech
from emiz.weather import AVWX, parse_metar_string

from esst.atis.identifier import get_random_identifier
from esst.atis.univers_radio import ALL_AIRFIELDS, ATISURSettings, URVoiceService
from esst.core import MAIN_LOGGER

LOGGER = MAIN_LOGGER.getChild(__name__)


class ATIS:
    """
    Manages ATIS
    """

    current_atis = {}

    def __init__(self):
        pass

    @classmethod
    def create_mp3_from_metar(cls, metar_str: str):
        """
        Create MP3 from METAR
        """
        URVoiceService.kill()
        LOGGER.info(f'creating ATIS from METAR: {metar_str}')
        LOGGER.debug('parsing METAR string')
        metar_str = metar_str.replace('XXXX', 'UGTB')
        error, metar = parse_metar_string(metar_str)
        if error:
            LOGGER.error('failed to parse METAR')
            raise RuntimeError(metar)
        wind_dir = metar.wind_dir.value()
        LOGGER.debug(f'wind direction: {wind_dir}')
        speech_atis = AVWX.metar_to_speech(metar_str)
        LOGGER.debug(f'ATIS speech: {speech_atis}')

        ur_settings = ATISURSettings()

        for airfield in ALL_AIRFIELDS:
            LOGGER.debug(f'processing airfield: {airfield.icao}')
            atis_file = Path(f'{airfield.icao}.mp3')
            LOGGER.debug(f'ATIS file path: {atis_file}')
            active_runway = airfield.get_active_runway(wind_dir)
            LOGGER.debug(f'active runway: {active_runway.long_name()}')
            speech_intro = f'ATIS for {airfield.name}'
            LOGGER.debug(f'ATIS intro: {speech_intro}')
            speech_active_runway = f'Active runway {active_runway.long_name()}'
            LOGGER.debug(f'active runway speech: {speech_active_runway}')
            speech_information = f'Advise you have information {get_random_identifier()} on first contact.'
            LOGGER.debug(f'speech information: {speech_information}')
            full_speech = '. '.join([speech_intro, speech_atis, speech_active_runway, speech_information])
            cls.current_atis[airfield.icao] = full_speech
            LOGGER.debug(f'full speech: {full_speech}')
            LOGGER.debug(f'writing MP3 file for: {airfield.icao}')
            text_to_speech(full_speech, Path(atis_file), True)
            ur_settings.add_station(airfield)

        LOGGER.debug('writing UR settings')
        ur_settings.write_settings_file()
        URVoiceService.start_service()
