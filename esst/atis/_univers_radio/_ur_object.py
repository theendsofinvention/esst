# coding=utf-8
# pylint: disable=too-few-public-methods
"""
Contains all objects relative to UR ATIS settings
"""
import re

import inflect


class URLinkType:
    """
    Setting that represents the type of link to an MP3 file, either local (on the system's hard drive) or remote (URL)
    """
    local_file = '1'
    url = '2'


class URFrequency:
    """
    Frequency for the ATIS

    Format: XXX.XXX;MOD
    Where XXX.XXX is the frequency and MOD is one of:
        A: AM
        F: FM
        S: SATCOM

    """
    ur_freq_re = re.compile(r'^\d{3}\.\d{3};[ASF]$')

    def __init__(self, freq: str) -> None:
        if not URFrequency.ur_freq_re.match(freq):
            raise ValueError()
        self.freq = freq

    def __str__(self):
        return self.freq

    def long_freq(self):
        """Returns nice frequency (123.456 AM)"""
        freq, mod = self.freq.split(';')
        if mod == 'S':
            mod = 'SATCOM'
        else:
            mod = f'{mod}M'
        return f'{freq} {mod}'


class URCoord:
    """
    Coordinates for an airfield (includes elevation)
    """
    ur_coord_re = re.compile(r'^-?\d{2,3}\.\d{6}$')
    ur_elev_re = re.compile(r'^\d+$')

    def __init__(self, lat: str, long: str, elev: str) -> None:
        if not URCoord.ur_coord_re.match(lat):
            raise ValueError(f'invalid latitude: {lat}')
        if not URCoord.ur_coord_re.match(long):
            raise ValueError(f'invalid longitude: {long}')
        if not URCoord.ur_elev_re.match(elev):
            raise ValueError(f'invalid elevation: {elev}')
        self.lat = lat
        self.long = long
        self.elev = str(int(elev) + 500)

    def __str__(self):
        return f'{self.lat};{self.long};{self.elev}'


class Runway:
    """
    Represents one or multiple runways
    """

    def __init__(self, heading: str) -> None:
        if 'L' in heading.upper():
            self._qualifier = 'L'
            self._long_qualifier = ' left'
            self._heading = heading.replace('L', '')
        elif 'R' in heading.upper():
            self._qualifier = 'R'
            self._long_qualifier = ' right'
            self._heading = heading.replace('R', '')
        else:
            self._qualifier = ''
            self._long_qualifier = ''
            self._heading = heading
        self._long_heading = ' '.join([inflect.engine().number_to_words(number) for number in self._heading])

    def __int__(self):
        try:
            return int(f'{self._heading}0')
        except ValueError:
            raise ValueError(self._heading)

    def __str__(self):
        return f'{self._heading}{self._qualifier}'

    def long_name(self):
        """

        Returns: long name of the airfield for use in ATIS speech

        """
        return f'{self._long_heading}{self._long_qualifier}'


# pylint: disable=too-many-arguments,too-few-public-methods
class Airfield:
    """
    Represents an airfield, complete with ICAO, name, ATIS frequency and available runways
    """

    def __init__(self, icao: str, name: str, coord: URCoord, atis_freq: URFrequency, runways: str) -> None:
        self.atis_freq = atis_freq
        self.coord = coord
        self.icao = icao
        self.name = name
        self.runways: list = []
        for runway in runways.split(','):
            self.runways.append(Runway(runway))

    def get_active_runway(self, wind_direction: int) -> Runway:
        """
        Returns the active runway depending on wind

        Args:
            wind_direction: wind direction in degrees

        Returns: active runway as a Runway instance

        """

        def diff_angle(angle1, angle2):
            """
            Computes the difference in degrees between two angles

            Args:
                angle1: first angle
                angle2: second angle

            Returns: absolute difference in degrees between the two angles

            """
            return abs((angle1 - angle2 + 180) % 360 - 180)

        result = []
        for runway in self.runways:
            result.append((diff_angle(int(runway), wind_direction), runway))

        return sorted(result, key=lambda x: x[0])[0][1]
