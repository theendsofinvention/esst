# coding=utf-8
"""
Manages ESST logging
"""

import logging
import logging.handlers
import os
import sys


def get_esst_log_file_path(saved_games_folder: str) -> str:
    """

    Args:
        saved_games_folder: path to the saved games folder

    Returns: path to log file

    """
    return os.path.join(saved_games_folder, 'Logs/esst.log')


def setup_logging(debug: bool, saved_games_folder: str) -> logging.Logger:
    """

    Args:
        debug: debug mode as a bool
        saved_games_folder: path to the saved games folder

    Returns: logger instance

    """
    logger = logging.getLogger('ESST')

    formatter = logging.Formatter('%(asctime)s %(levelname)8s %(name)s[%(lineno)d].%(funcName)s: %(message)s')

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)

    if os.path.exists(os.path.join(saved_games_folder, 'Logs')):
        file_handler = logging.handlers.TimedRotatingFileHandler(
            get_esst_log_file_path(saved_games_folder),
            when='midnight',
            backupCount=7
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    logger.setLevel(logging.DEBUG)
    logger.addHandler(console_handler)

    if debug:
        console_handler.setLevel(logging.DEBUG)
    else:
        console_handler.setLevel(logging.INFO)

    return logger
