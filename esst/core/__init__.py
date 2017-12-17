# coding=utf-8
"""
Globals
"""
import everett

# from .config import Config
from .new_config import ESSTConfig, validate_config, setup_config
from .context import Context, setup_context
from .logger import setup_logging
from .status import Status, ServerStatus

MAIN_LOGGER = setup_logging()
CTX = Context()
CFG = setup_config()
