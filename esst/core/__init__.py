# coding=utf-8
"""
Globals
"""
import everett

# from .config import Config
from .new_config import ESSTConfig, validate_config, setup_config
from .context import Context
from elib.custom_logging import get_logger
from .status import Status, ServerStatus

MAIN_LOGGER = get_logger(
    logger_name='ESST',
    log_to_file='esst.log',
    rotate_logs=True,
)
CTX = Context()
CFG = setup_config()
