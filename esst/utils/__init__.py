# coding=utf-8
"""
Various helper functions
"""
import os
from pathlib import Path
import typing
import datetime
import shutil

import pefile
import pkg_resources

from esst.core import MAIN_LOGGER, Status, CFG
from .remove_old_files import clean_all_folder
from .github import get_latest_release

LOGGER = MAIN_LOGGER.getChild(__name__)


def sanitize_path(path: typing.Union[str, Path]) -> str:
    """
    Sanitize a filesystem path

    Args:
        path: path to sanitize

    Returns: sanitized path as a string

    """
    return str(path).replace('\\', '/')


def create_versionned_backup(file_path: Path):
    """
    Creates a backup of a file, with a "_backup_DCS-VERSION" suffix, if the backup does not exist yet

    Args:
        file_path: file to backup

    """
    LOGGER.debug(f'checking for backup of {file_path}')
    if not file_path.exists():
        raise FileNotFoundError(file_path)
    backup_file = Path(file_path.parent, f'{file_path.name}_backup_{Status.dcs_version}')
    if not os.path.exists(backup_file):
        LOGGER.debug(f'creating backup of "{file_path}": "{backup_file}"')
        shutil.copy2(str(file_path), str(backup_file))
    else:
        LOGGER.debug(f'backup already exists: "{backup_file}"')


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
    template_path = os.path.join(os.path.dirname(
        __file__), 'templates', template_name)
    if not os.path.exists(template_path):
        LOGGER.debug('template not found, trying from pkg_resource')
        template_path = pkg_resources.resource_filename(
            'esst', f'/dcs/templates/{template_name}')
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
    return os.path.join(CFG.saved_games_dir, 'Logs/dcs.log')


class Win32FileInfo:  # pylint: disable=missing-docstring
    """
    Gets information about a Win32 portable executable
    """

    def __init__(self, _path):

        self.__path = os.path.abspath(_path)
        self.__props = None
        self.__read_props()

    @property
    def comments(self):
        return self.__props.get('Comments')

    @property
    def internal_name(self):
        return self.__props.get('InternalName')

    @property
    def product_name(self):
        return self.__props.get('ProductName')

    @property
    def company_name(self):
        return self.__props.get('CompanyName')

    @property
    def copyright(self):
        return self.__props.get('LegalCopyright')

    @property
    def product_version(self):
        return self.__props.get('ProductVersion')

    @property
    def file_description(self):
        return self.__props.get('FileDescription')

    @property
    def trademark(self):
        return self.__props.get('LegalTrademarks')

    @property
    def private_build(self):
        return self.__props.get('PrivateBuild')

    @property
    def file_version(self):
        return self.__props.get('FileVersion')

    @property
    def fixed_version(self):
        return self.__props.get('fixed_version')

    @property
    def original_filename(self) -> str:
        return self.__props.get('OriginalFilename')

    @property
    def special_build(self) -> str:
        return self.__props.get('SpecialBuild')

    def __read_props(self):

        def _loword(dword):
            return dword & 0x0000ffff

        def _hiword(dword):
            return dword >> 16

        self.__props = {}

        try:
            pe_file = pefile.PE(self.__path)
        except pefile.PEFormatError as exc:
            raise ValueError(exc.value)
        else:
            pvms = pe_file.VS_FIXEDFILEINFO.ProductVersionMS  # pylint: disable=no-member
            pvls = pe_file.VS_FIXEDFILEINFO.ProductVersionLS  # pylint: disable=no-member
            self.__props['fixed_version'] = '.'.join(
                map(str, (_hiword(pvms), _loword(pvms), _hiword(pvls), _loword(pvls)))
            )
            for file_info in pe_file.FileInfo:
                if file_info.Key == b'StringFileInfo':
                    for str_table in file_info.StringTable:
                        for entry in str_table.entries.items():
                            self.__props[entry[0].decode(
                                'latin_1')] = entry[1].decode('latin_1')
