# coding=utf-8
"""
Manages ESST logging
"""

import os
import logging.handlers
import sys

from esst.core.config import CFG

MAIN_LOGGER = logging.getLogger('ESST')

FORMATTER = logging.Formatter('%(asctime)s %(levelname)8s %(name)s: %(message)s')

CONSOLE_HANDLER = logging.StreamHandler(sys.stdout)
CONSOLE_HANDLER.setFormatter(FORMATTER)

FILE_HANDLER = logging.handlers.TimedRotatingFileHandler(
    os.path.join(CFG.saved_games_dir, 'Logs/esst.log'),
    when='midnight',
    backupCount=7
)
FILE_HANDLER.setFormatter(FORMATTER)

MAIN_LOGGER.setLevel(logging.DEBUG)
MAIN_LOGGER.addHandler(CONSOLE_HANDLER)
MAIN_LOGGER.addHandler(FILE_HANDLER)

if CFG.debug:
    MAIN_LOGGER.setLevel(logging.DEBUG)
else:
    MAIN_LOGGER.setLevel(logging.INFO)

__all__ = ['MAIN_LOGGER']
