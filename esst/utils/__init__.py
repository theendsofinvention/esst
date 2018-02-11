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

from esst.core import MAIN_LOGGER, Status, FS
from .arg import arg
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
    file_path = elib.path.ensure_file(file_path, must_exist=file_must_exist)
    backup_file = Path(file_path.parent, f'{file_path.name}_backup_{Status.dcs_version}')
    _do_backup(file_path, backup_file)


def create_simple_backup(file_path: typing.Union[str, Path], file_must_exist: bool = True):
    """
    Creates a backup of a file, with a "_backup_DCS-VERSION" suffix, if the backup does not exist yet

    Args:
        file_must_exist: fails if the file to be backed up does not exist
        file_path: file to backup

    """
    file_path = elib.path.ensure_file(file_path, must_exist=file_must_exist)
    backup_file = Path(file_path.parent, f'{file_path.name}_backup')
    _do_backup(file_path, backup_file)


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
    return os.path.join(FS.dcs_logs_dir, 'dcs.log')


class Win32FileInfo:
    """
    Gets information about a Win32 portable executable
    """

    def __init__(self, _path):

        self.__path = os.path.abspath(_path)
        self.__props = None
        self.__read_props()

    @property
    def comments(self):
        """Show Win32FileInfo field"""
        return self.__props.get('Comments')

    @property
    def internal_name(self):
        """Show Win32FileInfo field"""
        return self.__props.get('InternalName')

    @property
    def product_name(self):
        """Show Win32FileInfo field"""
        return self.__props.get('ProductName')

    @property
    def company_name(self):
        """Show Win32FileInfo field"""
        return self.__props.get('CompanyName')

    @property
    def copyright(self):
        """Show Win32FileInfo field"""
        return self.__props.get('LegalCopyright')

    @property
    def product_version(self):
        """Show Win32FileInfo field"""
        return self.__props.get('ProductVersion')

    @property
    def file_description(self):
        """Show Win32FileInfo field"""
        return self.__props.get('FileDescription')

    @property
    def trademark(self):
        """Show Win32FileInfo field"""
        return self.__props.get('LegalTrademarks')

    @property
    def private_build(self):
        """Show Win32FileInfo field"""
        return self.__props.get('PrivateBuild')

    @property
    def file_version(self):
        """Show Win32FileInfo field"""
        return self.__props.get('FileVersion')

    @property
    def fixed_version(self):
        """Show Win32FileInfo field"""
        return self.__props.get('fixed_version')

    @property
    def original_filename(self) -> str:
        """Show Win32FileInfo field"""
        return self.__props.get('OriginalFilename')

    @property
    def special_build(self) -> str:
        """Show Win32FileInfo field"""
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
            # noinspection SpellCheckingInspection
            pvms = pe_file.VS_FIXEDFILEINFO.ProductVersionMS  # pylint: disable=no-member
            # noinspection SpellCheckingInspection
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
