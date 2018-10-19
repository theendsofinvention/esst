# coding=utf-8
"""
ESST ATIS package
"""

import elib_wx

from esst import ATISConfig, LOGGER
from esst.core import CTX
from ._atis_status import Status as _ATISStatus
from ._univers_radio import Status as _URStatus, discover_ur_install_path


def init_atis_module():
    """
    Initialize the ATIS module
    """
    LOGGER.info('initializing ATIS module')
    discover_ur_install_path()
    if CTX.sentry:
        LOGGER.debug('registering ATIS contexts for Sentry')
        CTX.sentry.register_context(context_name='ATIS', context_provider=_ATISStatus)
        CTX.sentry.register_context(context_name='UR', context_provider=_URStatus)
    elib_wx.Config.dummy_icao_code = ATISConfig.DEFAULT_ICAO()
