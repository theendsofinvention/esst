# coding=utf-8
"""
Main ESST logger is setup here, as well as the logging configuration of other libraries
"""

import logging
import sys

_ROOT_LOGGER = logging.getLogger('')
LOGGER = logging.getLogger('ESST')
_LOGGING_SPARSE_FORMAT = logging.Formatter(
    '%(relativeCreated)10d ms '
    '%(levelname)8s: '
    '%(message)s'
)
_LOGGING_VERBOSE_FORMAT = logging.Formatter(
    '%(relativeCreated)10d ms '
    '%(processName)15s '
    '%(threadName)15s '
    '%(levelname)8s '
    '%(name)s '
    '[%(pathname)s@%(lineno)d %(funcName)s]: '
    '%(message)s'
)
LOGGING_CONSOLE_HANDLER = logging.StreamHandler(stream=sys.stdout)
LOGGING_CONSOLE_HANDLER.setLevel(logging.INFO)
if hasattr(sys, 'frozen'):
    LOGGING_CONSOLE_HANDLER.setFormatter(_LOGGING_SPARSE_FORMAT)
else:
    LOGGING_CONSOLE_HANDLER.setFormatter(_LOGGING_VERBOSE_FORMAT)
_LOGGING_FILE_HANDLER = logging.FileHandler('esst.log', mode='w', encoding='utf8')
_LOGGING_FILE_HANDLER.setLevel(logging.DEBUG)
_LOGGING_FILE_HANDLER.setFormatter(_LOGGING_VERBOSE_FORMAT)
_ROOT_LOGGER.addHandler(LOGGING_CONSOLE_HANDLER)
_ROOT_LOGGER.addHandler(_LOGGING_FILE_HANDLER)
_ROOT_LOGGER.setLevel(logging.DEBUG)
logging.getLogger('ELIB').setLevel(logging.INFO)
logging.getLogger('EMIZ').setLevel(logging.INFO)
logging.getLogger('git').setLevel(logging.INFO)
logging.getLogger('urllib3').setLevel(logging.INFO)
logging.getLogger('discord').setLevel(logging.INFO)
logging.getLogger('websockets').setLevel(logging.INFO)
logging.getLogger('matplotlib').setLevel(logging.INFO)
LOGGER.debug('logger setup complete')
