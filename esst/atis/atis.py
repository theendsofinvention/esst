# coding=utf-8
"""
Manages ATIS services
"""

from pathlib import Path

from elib.tts import text_to_speech
from emiz.weather import AVWX, parse_metar_string

from esst.atis.identifier import get_random_identifier
from esst.atis.univers_radio import ALL_AIRFIELDS, URVoiceService, URVoiceServiceSettings
from esst.core import MAIN_LOGGER

LOGGER = MAIN_LOGGER.getChild(__name__)


class ATISForAirfield:
    """Simple data class for airfield ATIS information"""

    def __init__(
            self,
            icao,
            active_runway,
            info_identifier,
    ):
        self.icao = icao
        self.active_runway = active_runway
        self.info_id = info_identifier


class ATIS:
    """
    Manages ATIS
    """

    current_atis = {}

    @classmethod
    def get_info_for_icao(cls, icao: str) -> ATISForAirfield:
        """Returns ATIS information for icao"""
        return cls.current_atis[icao]

    @classmethod
    def _build_speech_for_airfield(cls, airfield, wind_dir, speech_atis, ur_settings):
        LOGGER.debug(f'processing airfield: {airfield.icao}')
        atis_file = Path(f'{airfield.icao}.mp3').absolute()
        LOGGER.debug(f'ATIS file path: {atis_file}')
        active_runway = airfield.get_active_runway(wind_dir)
        LOGGER.debug(f'active runway: {active_runway.long_name()}')
        speech_intro = f'ATIS for {airfield.name}'
        LOGGER.debug(f'ATIS intro: {speech_intro}')
        speech_active_runway = f'Active runway {active_runway.long_name()}'
        LOGGER.debug(f'active runway speech: {speech_active_runway}')
        information_identifier = get_random_identifier()
        speech_information = f'Advise you have information {information_identifier} on first contact.'
        LOGGER.debug(f'speech information: {speech_information}')
        full_speech = '. '.join([speech_intro, speech_atis, speech_active_runway, speech_information])
        cls.current_atis[airfield.icao] = ATISForAirfield(airfield.icao, active_runway, information_identifier)
        LOGGER.debug(f'full speech: {full_speech}')
        LOGGER.debug(f'writing MP3 file for: {airfield.icao}')
        text_to_speech(full_speech, Path(atis_file), True)
        ur_settings.add_station(airfield)

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

        ur_settings = URVoiceServiceSettings()

        for airfield in ALL_AIRFIELDS:
            cls._build_speech_for_airfield(airfield, wind_dir, speech_atis, ur_settings)

        LOGGER.debug('writing UR settings')
        ur_settings.write_settings_file()
        URVoiceService.start_service()
