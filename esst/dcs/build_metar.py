# coding=utf-8

import datetime
import re

from emft.miz import Mission, Miz
from emft.miz.mission_weather import MissionWeather


def _get_wind(mission):
    wind_dir = MissionWeather._reverse_direction(mission.weather.wind_at_ground_level_dir)
    wind_speed = int(mission.weather.wind_at_ground_level_speed)
    return f'{wind_dir:03}{wind_speed:02}MPS'


def _get_precip(mission: Mission):
    precip = {
        0: '',
        1: 'RA',
        2: 'SN',
        3: '+RA',
        4: '+SN',
    }
    return precip[mission.weather.precipitations]


def _get_clouds(mission: Mission):
    density = {
        0: 'CLR',
        1: 'FEW',
        2: 'FEW',
        3: 'FEW',
        4: 'SCT',
        5: 'SCT',
        6: 'SCT',
        7: 'BKN',
        8: 'BKN',
        9: 'OVC',
        10: 'OVC',
    }
    density = density[mission.weather.cloud_density]
    base = int(round(mission.weather.cloud_base * 3.28084, -2))
    return f'{density}{base:04}'


def _get_temp(mission: Mission):
    temp = mission.weather.temperature
    minus = 'M' if temp < 0 else ''
    temp = abs(temp)
    return f'{minus}{temp:02}'


def _get_pressure(mission: Mission):
    pres = mission.weather.qnh
    hpa = round(pres / 0.75006156130264)
    return f'Q{hpa}'


def build_metar(mission_file: str,
                icao: str,
                time: str = None,
                ):
    if time is None:
        now = datetime.datetime.utcnow()
        day = now.day
        hour = now.hour
        minute = now.minute
        time = f'{day:02}{hour:02}{minute:02}Z'
    with Miz(mission_file) as miz:
        mission = miz.mission
    wind = _get_wind(mission)
    visibility = min(mission.weather.visibility, 10000)
    precip = _get_precip(mission)
    clouds = _get_clouds(mission)
    temp = _get_temp(mission)
    pres = _get_pressure(mission)
    qual = 'NOSIG'

    if visibility == 10000 and int(round(mission.weather.cloud_base * 3.28084, -2)) >= 5000:
        visibility = 'CAVOK'

    metar = f'{icao} {time} {wind} {visibility} {precip} {clouds} {temp} {pres} {qual}'
    return re.sub(' +', ' ', metar)
