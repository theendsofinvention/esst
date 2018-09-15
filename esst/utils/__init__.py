# coding=utf-8
"""
Various helper functions
"""
import datetime
import os
import shutil
import typing
from pathlib import Path

import elib
import ipgetter
import pefile
import pkg_resources

from esst.core import FS, MAIN_LOGGER, Status
from .arg import arg
from .find_port import assign_ports
from .github import get_latest_release
from .remove_old_files import clean_all_folder

LOGGER = MAIN_LOGGER.getChild(__name__)


def external_ip():
    """
    Returns: external IP of this machine
    """
    return ipgetter.IPgetter().get_externalip()


def sanitize_path(path: typing.Union[str, Path]) -> str:
    """
    Sanitize a filesystem path

    Args:
        path: path to sanitize

    Returns: sanitized path as a string

    """
    return str(path).replace('\\', '/')


def _do_backup(original: Path, backup: Path):
    LOGGER.debug(f'checking for backup of {original.absolute()}')
    if not original.exists():
        LOGGER.debug(f'original does no exist, skipping backup: {original.absolute()}')
        return
    if not backup.exists():
        LOGGER.debug(f'creating backup of "{original.absolute()}" -> "{backup.absolute()}"')
        shutil.copy2(str(original.absolute()), str(backup.absolute()))
    else:
        LOGGER.debug(f'backup already exists: "{backup.absolute()}"')


def create_versioned_backup(file_path: typing.Union[str, Path], file_must_exist: bool = True):
    """
    Creates a backup of a file, with a "_backup_DCS-VERSION" suffix, if the backup does not exist yet

    Args:
        file_must_exist: fails if the file to be backed up does not exist
        file_path: file to backup

    """
    file_path_as_path = elib.path.ensure_file(file_path, must_exist=file_must_exist)
    backup_file = Path(file_path_as_path.parent, f'{file_path_as_path.name}_backup_{Status.dcs_version}')
    _do_backup(file_path_as_path, backup_file)


def create_simple_backup(file_path: typing.Union[str, Path], file_must_exist: bool = True):
    """
    Creates a backup of a file, with a "_backup_DCS-VERSION" suffix, if the backup does not exist yet

    Args:
        file_path: file to backup
        file_must_exist: fails if the file to be backed up does not exist

    """
    file_path_as_path: Path = elib.path.ensure_file(file_path, must_exist=file_must_exist)
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
    LOGGER.debug(f'reading template: {template_name}')
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
    return os.path.join(str(FS.dcs_logs_dir.absolute()), 'dcs.log')


def _parse_file_info(file_info_list) -> typing.Optional[str]:
    for _file_info in file_info_list:
        if _file_info.Key == b'StringFileInfo':  # pragma: no branch
            for string in _file_info.StringTable:  # pragma: no branch
                print(string.entries.keys())
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
