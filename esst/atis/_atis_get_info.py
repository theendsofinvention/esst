# coding=utf-8
"""
Retrieves info about currently running ATIS
"""

from ._atis_objects import ATISForAirfield as _ATISForAirfield
from ._atis_status import Status as _Status


def get_info_for_icao(icao: str) -> _ATISForAirfield:
    """Returns ATIS information for icao"""
    icao = icao.upper()
    return _Status.active_atis[icao]
