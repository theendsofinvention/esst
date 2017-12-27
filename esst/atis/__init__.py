# coding=utf-8
"""
Interface to the ATIS package
"""

import typing

from esst import core as _core
from ._atis_generator import generate_atis as _generate_atis
from ._atis_get_info import get_info_for_icao as _get_info_for_icao
from ._atis_status import Status as _ATISStatus
from ._univers_radio import Status as _URStatus

_LOGGER = _core.MAIN_LOGGER.getChild(__name__)


def generate_atis(
        metar_str: str,
        include_icao: typing.List[str] = None,
        exclude_icao: typing.List[str] = None):
    """
    Create ATIS from METAR

    Args:
        metar_str: METAR
        include_icao: list of ICAO to include
        exclude_icao: list of ICAO to exclude

    """
    _generate_atis(metar_str, include_icao, exclude_icao)


def get_info_from_icao(icao: str):
    """
    Retrieves ATIS information for ICAO

    Args:
        icao: ICAO string
    """
    _get_info_for_icao(icao)


def init_module():
    """
    Initialize the ATIS module
    """
    from ._univers_radio import discover_ur_install_path
    discover_ur_install_path()
    if _core.CTX.sentry:
        _core.CTX.sentry.register_context(context_name='ATIS', context_provider=_ATISStatus)
        _core.CTX.sentry.register_context(context_name='UR', context_provider=_URStatus)
