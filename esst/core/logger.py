# coding=utf-8
"""
Manages ESST logging
"""

import logging
import logging.handlers
import os
import sys


def get_esst_log_file_path() -> str:
    """

    Args:
        saved_games_folder: path to the saved games folder

    Returns: path to log file

    """
    return '.esst.log'


def setup_logging(debug: bool) -> logging.Logger:
    """

    Args:
        debug: debug mode as a bool

    Returns: logger instance

    """
    logger = logging.getLogger('ESST')

    formatter = logging.Formatter(
        '%(asctime)s %(levelname)8s %(name)s[%(lineno)d].%(funcName)s: %(message)s')

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)

    file_handler = logging.handlers.TimedRotatingFileHandler(
        get_esst_log_file_path(),
        when='midnight',
        backupCount=7
    )
    file_handler.setFormatter(formatter)

    logger.setLevel(logging.DEBUG)
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    if debug:
        console_handler.setLevel(logging.DEBUG)
    else:
        console_handler.setLevel(logging.INFO)

    return logger
