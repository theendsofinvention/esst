# coding=utf-8
"""
Manages UR settings
"""

from pathlib import Path

from esst.atis.univers_radio.ur_object import Airfield, URLinkType
from esst.core import MAIN_LOGGER, FS
from esst.utils import create_versioned_backup

LOGGER = MAIN_LOGGER.getChild(__name__)


def on_esst_start():
    FS.ur_folder = Path(FS.saved_games_path, 'UniversRadio')
    FS.ur_settings_file = Path(FS.ur_folder, 'VoiceService.dat')
    create_versioned_backup(FS.ur_folder, file_must_exist=False)


class ATISURSettings:
    """
    Manages UR settings
    """

    def __init__(self):
        LOGGER.debug('creating UR settings instance')
        self._stations = []

    def add_station(self, airfield: Airfield):
        """
        Adds a station

        Args:
            airfield: station to add

        """
        LOGGER.debug(f'adding {airfield.icao} to UR settings')
        mp3_file = Path(f'./{airfield.icao}.mp3')
        station_line = ';'.join([
            str(URLinkType.local_file),
            str(airfield.atis_freq),
            str(airfield.coord),
            f'[{str(mp3_file.absolute())}]'
        ])
        LOGGER.debug(f'station line: {station_line}')
        self._stations.append(station_line)

    def write_settings_file(self):
        """
        Writes currently known station to UR settings file
        """
        LOGGER.debug(f'writing UR settings to: {FS.ur_settings_file}')
        stations = '\n'.join(self._stations)
        full_text = f'Start of VSS DB\n{stations}\nEnd of VSS DB'
        FS.ur_settings_file.write_text(full_text)
