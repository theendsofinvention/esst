# coding=utf-8

import datetime
import os

import parsedatetime

from esst.core import CFG, MAIN_LOGGER

LOGGER = MAIN_LOGGER.getChild(__name__)


def _parse_age_string(age_str):
    # noinspection PyUnresolvedReferences
    time_struct, parse_status = parsedatetime.Calendar().parse(age_str)
    if parse_status != 1:
        LOGGER.error(f'unable to parse age: {age_str}')
        return False
    return datetime.datetime(*time_struct[:6]).timestamp()


def _remove_old_files(folder, age):
    LOGGER.info(f'cleaning folder "{folder}" of all files older than {age}')

    age = _parse_age_string(age)
    if not age:
        return

    for root, _, files in os.walk(folder):
        for file in files:
            file = os.path.abspath(os.path.join(root, file))
            creation_time = os.path.getctime(file)
            LOGGER.debug(f'"{file}" creation time: {creation_time}')
            if creation_time <= age:
                LOGGER.info(f'removing: {file}')
                os.unlink(file)


def clean_all_folder():
    """
    Cleans all folders according to current config
    """
    paths_to_clean = CFG.remove_files
    if paths_to_clean:
        for remove_config in paths_to_clean:
            name = tuple(remove_config.keys())[0]
            LOGGER.info(f'processing: {name}')
            remove_config = remove_config[name]
            if 'folder' not in remove_config.keys():
                LOGGER.error(f'missing "folder" in {name}')
                return
            if 'age' not in remove_config.keys():
                LOGGER.error(f'missing "age" in {name}')
                return
            if not os.path.exists(remove_config['folder']):
                LOGGER.error(f'path does not exist: {remove_config["folder"]}')
                return
            _remove_old_files(**remove_config)
    else:
        LOGGER.debug('no folder to clean')
