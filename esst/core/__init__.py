# coding=utf-8
"""
Globals
"""
import everett

# from .config import Config
from esst import __version__
from .new_config import ESSTConfig
from .context import Context
from .logger import setup_logging
from .status import Status, ServerStatus

CTX = Context()

try:
    CFG = ESSTConfig()
    MAIN_LOGGER = setup_logging(CFG.debug, CFG.saved_games_dir)
except everett.InvalidValueError as exception:
    KEY = exception.key
    if exception.namespace:
        KEY = f'{exception.namespace}_{KEY}'
    print(f'Invalid config value: {KEY}')
    exit(1)
except everett.ConfigurationMissingError as exception:
    KEY = exception.key
    if exception.namespace:
        KEY = f'{exception.namespace}_{KEY}'
    print(f'Missing configuration value: {KEY}')
    exit(1)
