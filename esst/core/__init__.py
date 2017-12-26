# coding=utf-8
"""
Globals
"""
import logging.handlers

import elib
# noinspection PyUnresolvedReferences
import emiz

from esst import __version__
from .context import Context
from .fs_paths import FS
# from .config import Config
from .new_config import ESSTConfig, setup_config, validate_config
from .status import ServerStatus, Status

MAIN_LOGGER = elib.get_logger(
    logger_name='ESST',
    log_to_file='esst.log',
    rotate_logs=True,
)

MAIN_LOGGER.info(f'ESST version {__version__}')

EMIZ_LOGGER = logging.getLogger('EMIZ')
ELIB_LOGGER = logging.getLogger('ELIB')

for logger in (EMIZ_LOGGER, ELIB_LOGGER):
    for handler in logger.handlers:
        MAIN_LOGGER.debug(f'removing {handler} from {logger}')
        logger.removeHandler(handler)

for handler in MAIN_LOGGER.handlers:
    EMIZ_LOGGER.addHandler(handler)
    ELIB_LOGGER.addHandler(handler)

CTX = Context()
CFG = setup_config()
