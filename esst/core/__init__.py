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
from .new_config import ESSTConfig, validate_config
from .new_config.setup_config import setup_config
from .status import ServerStatus, Status

MAIN_LOGGER = elib.custom_logging.get_logger(
    logger_name='ESST',
    log_to_file=True,
    use_click_handler=True,
    rotate_logs=True,
)
elib.custom_logging.set_root_logger(MAIN_LOGGER)

MAIN_LOGGER.info('ESST version %s', __version__)

EMIZ_LOGGER = logging.getLogger('EMIZ')
ELIB_LOGGER = logging.getLogger('ELIB')

for logger in (EMIZ_LOGGER, ELIB_LOGGER):
    for handler in logger.handlers:
        MAIN_LOGGER.debug('removing %s from %s', handler, logger.name)
        logger.removeHandler(handler)

for handler in MAIN_LOGGER.handlers:
    EMIZ_LOGGER.addHandler(handler)
    ELIB_LOGGER.addHandler(handler)

CTX = Context()
MAIN_LOGGER.info('reading config')
CFG = setup_config()
