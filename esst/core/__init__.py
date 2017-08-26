# coding=utf-8

import everett

from .config import Config
from .context import Context
from .logger import setup_logging
from .status import Status
from .version import __version__

try:
    CFG = Config(__version__)
    CTX = Context()
    MAIN_LOGGER = setup_logging(CFG.debug, CFG.saved_games_dir)
except everett.InvalidValueError as exception:
    KEY = exception.key
    if exception.namespace:
        KEY = f'{exception.namespace}_{KEY}'
    print(f'Invalid value for key: {KEY}')
    exit(1)
except everett.ConfigurationMissingError as exception:
    KEY = exception.key
    if exception.namespace:
        KEY = f'{exception.namespace}_{KEY}'
    print(f'Missing configuration for key: {KEY}')
    exit(1)
