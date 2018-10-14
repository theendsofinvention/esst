# coding=utf-8
"""
Weather related commands
"""

import elib_wx

from esst import commands, utils


@utils.arg('metar_or_icao', help='update the weather from a given (real life) ICAO or a plain (valid) '
                                 'METAR string\n'
                                 'WARNING: loading from a METAR string does not currently work')
def show(metar_or_icao: str):
    """
    Displays the weather for an arbitrary given ICAO or METAR string
    """
    _weather = elib_wx.Weather(metar_or_icao)
    message = f'Weather for: {metar_or_icao}\n\n' \
              f'METAR:\n{_weather.raw_metar_str}\n\n' \
              f'Weather:\n{_weather.as_str()}\n\n' \
              f'DCS weather (warning: this is an example only, a different DCS weather will be generated each time):' \
              f'\n{_weather.generate_dcs_weather()}'
    commands.DISCORD.say(message)


NAMESPACE = '!weather'
TITLE = 'Sneak-peak of weather objects'
