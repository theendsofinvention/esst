# coding=utf-8
"""
Various helper functions
"""
import datetime
import os
import shutil
import typing
from pathlib import Path

import pefile
import pkg_resources
import requests

from esst import LOGGER
from esst.core import Status
# from esst.core.fs_paths import FS
from .arg import arg
from .find_port import assign_ports
from .github import get_latest_release
from .remove_old_files import clean_all_folder


def external_ip():
    """
    Returns: external IP of this machine
    """
    try:
        return requests.get('https://api.ipify.org').text
    except requests.ConnectionError:
        LOGGER.error('unable to obtain external IP')
        return 'unknown'


def sanitize_path(path: typing.Union[str, Path]) -> str:
    """
    Sanitize a filesystem path

    Args:
        path: path to sanitize

    Returns: sanitized path as a string

    """
    return str(path).replace('\\', '/')


def check_path(*path: typing.Union[str, Path], must_exist: bool = True) -> Path:
    """
    Verifies a Path object

    :param path: path to check
    :type path: Path
    :param must_exist: set to True if Path must exist
    :type must_exist: bool
    :return: verified Path
    :rtype: Path
    :raises : FileNotFoundError if Path must exist but isn't found
    """
    _path = Path(*path).absolute()
    if must_exist and not _path.exists():
        raise FileNotFoundError(str(_path))
    return _path.absolute()


def check_file(*file_path: typing.Union[str, Path], must_exist: bool = True) -> Path:
    """
    Verifies a Path object as a file

    :param file_path: path to check
    :type file_path: Path
    :param must_exist: set to True if Path must exist
    :type must_exist: bool
    :return: verified Path
    :rtype: Path
    :raises : FileNotFoundError if Path must exist but isn't found
    :raises : TypeError if Path isn't a file
    """
    _file_path = check_path(*file_path, must_exist=must_exist)
    if _file_path.exists():
        if not _file_path.is_file():
            raise TypeError(f'not a file: {str(_file_path.absolute())}')
    return _file_path


def check_dir(*dir_path: typing.Union[str, Path], must_exist: bool = True, create: bool = False) -> Path:
    """
    Verifies a Path object as a directory

    :param dir_path: path to check
    :type dir_path: Path
    :param must_exist: set to True if Path must exist
    :type must_exist: bool
    :param create: set to True if the Path should be created
    :type create: bool
    :return: verified Path
    :rtype: Path
    :raises : FileNotFoundError if Path must exist but isn't found
    :raises : TypeError if Path isn't a directory
    """
    must_exist = not create if create else must_exist
    _dir_path = check_path(*dir_path, must_exist=must_exist)
    if _dir_path.exists():
        if not _dir_path.is_dir():
            raise TypeError(f'not a directory: {str(_dir_path.absolute())}')
    else:
        if create:
            _dir_path.mkdir(parents=True)
    return _dir_path


def _do_backup(original: Path, backup: Path):
    LOGGER.debug('%s: checking for backup', original.absolute())
    if not original.exists():
        LOGGER.debug('%s: original does no exist, skipping backup', original.absolute())
        return
    if not backup.exists():
        LOGGER.debug('%s: creating backup: %s', original.absolute(), backup.absolute())
        shutil.copy2(str(original.absolute()), str(backup.absolute()))
    else:
        LOGGER.debug('%s: backup already exists', backup.absolute())


def create_versioned_backup(file_path: typing.Union[str, Path], file_must_exist: bool = True):
    """
    Creates a backup of a file, with a "_backup_DCS-VERSION" suffix, if the backup does not exist yet

    Args:
        file_must_exist: fails if the file to be backed up does not exist
        file_path: file to backup

    """
    file_path_as_path = check_file(file_path, must_exist=file_must_exist)
    backup_file = Path(file_path_as_path.parent, f'{file_path_as_path.name}_backup_{Status.dcs_version}')
    _do_backup(file_path_as_path, backup_file)


def create_simple_backup(file_path: typing.Union[str, Path], file_must_exist: bool = True):
    """
    Creates a backup of a file, with a "_backup_DCS-VERSION" suffix, if the backup does not exist yet

    Args:
        file_path: file to backup
        file_must_exist: fails if the file to be backed up does not exist

    """
    file_path_as_path = check_file(file_path, must_exist=file_must_exist)
    backup_file = Path(file_path_as_path.parent, f'{file_path_as_path.name}_backup')
    _do_backup(file_path_as_path, backup_file)


def now():
    """

    Returns: epoch

    """
    return datetime.datetime.now().timestamp()


def read_template(template_name: str) -> str:
    """
    Reads a template file, getting it from the local install or from the package

    Args:
        template_name: name of the template file

    Returns: template file content

    """
    LOGGER.debug('reading template: %s', template_name)
    template_path = os.path.join(os.path.dirname(__file__), 'templates', template_name)
    if not os.path.exists(template_path):
        LOGGER.debug('template not found, trying from pkg_resource')
        template_path = pkg_resources.resource_filename('esst', f'/dcs/templates/{template_name}')
    if not os.path.exists(template_path):
        raise FileNotFoundError(template_path)
    with open(template_path) as handle_:
        LOGGER.debug('returning template content')
        return handle_.read()


def get_esst_changelog_path() -> str:
    """

    Returns: changelog path

    """
    changelog_path = os.path.join(os.path.dirname(__file__), 'CHANGELOG.rst')
    if not os.path.exists(changelog_path):
        LOGGER.debug('changelog not found, trying from pkg_resource')
        changelog_path = pkg_resources.resource_filename(
            'esst', 'CHANGELOG.rst')
    if not os.path.exists(changelog_path):
        LOGGER.error('changelog not found')
        return ''

    return changelog_path


def get_dcs_log_file_path() -> str:
    """
    Returns: path to DCS log file
    """
    from esst import FS
    _log_dir_path = str(FS.dcs_logs_dir.absolute())  # type: ignore
    return os.path.join(_log_dir_path, 'dcs.log')


def _parse_file_info(file_info_list) -> typing.Optional[str]:
    for _file_info in file_info_list:
        if _file_info.Key == b'StringFileInfo':  # pragma: no branch
            for string in _file_info.StringTable:  # pragma: no branch
                if b'FileVersion' in string.entries.keys():  # pragma: no branch
                    file_version = string.entries[b'FileVersion'].decode('utf8')
                    return file_version
    return None


# pylint: disable=inconsistent-return-statements
def get_product_version(path: typing.Union[str, Path]) -> str:
    """
    Get version info from executable

    Args:
        path: path to the executable

    Returns: VersionInfo
    """
    path = Path(path).absolute()
    pe_info = pefile.PE(str(path))

    try:
        for file_info in pe_info.FileInfo:  # pragma: no branch
            if isinstance(file_info, list):
                result = _parse_file_info(file_info)
                if result:
                    return result
            else:
                result = _parse_file_info(pe_info.FileInfo)
                if result:
                    return result

        raise RuntimeError(f'unable to obtain version from {path}')
    except (KeyError, AttributeError) as exc:
        raise RuntimeError(f'unable to obtain version from {path}') from exc
