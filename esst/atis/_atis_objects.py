# coding=utf-8
"""
Manages ATIS objects
"""

from attr import attrib, attrs


@attrs
class ATISForAirfield:
    """Simple data class for airfield ATIS information"""
    icao = attrib()
    active_runway = attrib()
    info_id = attrib()
    info_letter = attrib()
