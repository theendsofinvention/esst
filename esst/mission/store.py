# coding=utf-8
"""
Manages the local repositories and mission files
"""
import sys
import typing
import uuid
from pathlib import Path

from esst import FS, LOGGER


def _get_mission_folder(*paths: typing.Union[str, Path]) -> Path:
    """
    Returns a directory on the filesystem, creating it if necessary, and ensuring that no file exists at the location

    Args:
        *paths: list of paths to concatenate

    Returns: Path object

    """
    path = Path(*paths)
    if path.exists() and path.is_file():
        raise RuntimeError(f'path already exists but is a file: "{path}"')
    if not path.exists():
        LOGGER.debug('creating directory: %s', str(path))
        path.mkdir(parents=True)
    return path


def get_base_missions_folder() -> Path:
    """
    Returns the folder in which all ESST related missions are contained

    Returns: Path object

    """
    if FS.dcs_mission_folder:
        return FS.dcs_mission_folder

    LOGGER.error('FS.dcs_mission_folder undefined')
    sys.exit(1)


def get_auto_missions_folder() -> Path:
    """
    Returns the folder in which missions modified by ESST are stored

    Returns: Path object

    """
    return _get_mission_folder(get_base_missions_folder(), 'AUTO')


def get_random_auto_mission_name(source_mission: Path) -> Path:
    """
    Creates a random name for a mission to be modified

    Args:
        source_mission: path to the source mission

    Returns: random mission path

    """
    if not source_mission.is_file():
        raise RuntimeError(f'source_mission if not a file: {source_mission}')
    if source_mission.suffix != '.miz':
        raise RuntimeError(
            f'source_mission if not a MIZ file: {source_mission}')
    _id = str(uuid.uuid4())[:8]
    _tmp_name = source_mission.stem
    _tmp_path = Path(get_auto_missions_folder(), f'{_tmp_name}_{_id}.miz')
    return _tmp_path


def list_missions():
    """
    List all missions available for loading
    """
    for file in get_auto_missions_folder().iterdir():
        yield file


def clean():
    """
    Removes all mission files contained in the auto folder
    """
    for file in get_auto_missions_folder().iterdir():
        yield file
