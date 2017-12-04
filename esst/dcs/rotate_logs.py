# coding=utf-8

import os
from pathlib import Path
import datetime

from esst.core import CFG, MAIN_LOGGER
from esst.utils.remove_old_files import remove_file_if_older_than, parse_age_string

LOGGER = MAIN_LOGGER.getChild(__name__)


def _log_dir() -> Path:
    return Path(CFG.saved_games_dir, 'logs')


def _save_old_log(old_log: Path):
    stat = old_log.stat()
    creation_time = datetime.datetime.fromtimestamp(stat.st_mtime)
    old_log.rename(Path(old_log.parent, f'{creation_time.strftime("%Y%m%d%H%M%S")}.dcs.log'))


def rotate_dcs_log():
    LOGGER.info('rotating DCS logs')
    log_dir = _log_dir()
    LOGGER.debug(f'using logs directory: {log_dir}')
    if not log_dir.exists():
        LOGGER.error('log directory does no exist')
        return
    old_log = log_dir.joinpath('dcs.log.old')
    if old_log.exists():
        LOGGER.debug('saving old log')
        _save_old_log(old_log)
    else:
        LOGGER.info('no old log found')


def clean_old_logs():
    if CFG.dcs_delete_logs_older_than:
        age = parse_age_string(CFG.dcs_delete_logs_older_than)
        if not age:
            LOGGER.error(f'invalid value for "dcs_keep_logs_for": {CFG.dcs_keep_logs_for}')
            return
        LOGGER.info('removing old DCS logs')
        log_dir = _log_dir()
        LOGGER.debug(f'using logs directory: {log_dir}')
        if not log_dir.exists():
            LOGGER.error('log directory does no exist')
            return
        for file in log_dir.glob('*.dcs.log'):
            remove_file_if_older_than(file, age)
    else:
        LOGGER.info('not removing old logs; no age limit given in config')


if __name__ == '__main__':
    clean_old_logs()
    # rotate_dcs_log()

