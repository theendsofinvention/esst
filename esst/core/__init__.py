# coding=utf-8
"""
Globals
"""

from elib.custom_logging import get_logger

from .context import Context
# from .config import Config
from .new_config import ESSTConfig, setup_config, validate_config
from .status import ServerStatus, Status

MAIN_LOGGER = get_logger(
    logger_name='ESST',
    log_to_file='esst.log',
    rotate_logs=True,
)
CTX = Context()
CFG = setup_config()
