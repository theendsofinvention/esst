# coding=utf-8
"""
Manages UR installation path
"""
import sys
import typing
from pathlib import Path

from esst import ATISConfig, LOGGER, utils
from ._ur_status import Status as URStatus

try:
    import winreg
except ImportError:
    from unittest.mock import MagicMock

    winreg = MagicMock()

A_REG = winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER)


def _get_ur_install_path_from_registry() -> typing.Union[Path, None]:
    LOGGER.debug('searching for base "Saved Games" folder')
    try:
        with winreg.OpenKey(A_REG, r"Software\sSoft\UniversRadio") as key:
            # noinspection SpellCheckingInspection
            return Path(winreg.QueryValueEx(key, "Install_Dir")[0])
    except FileNotFoundError:
        return None


def discover_ur_install_path():
    """
    Tries to find Saved Games on this system

    Returns: Saved Games dir
    """
    from esst import FS
    LOGGER.debug('discovering UR install path')
    if not ATISConfig.UR_PATH():
        LOGGER.debug('no UR install path in Config, looking it up in the registry')
        _ur_install_path = _get_ur_install_path_from_registry()

    else:
        LOGGER.debug('UR install path found in Config')
        _ur_install_path = Path(ATISConfig.UR_PATH())
        if not _ur_install_path.is_dir():
            LOGGER.error('UR install path provided in config file is not a directory: %s', _ur_install_path)
            sys.exit(1)

    LOGGER.debug('using UR install path: %s', _ur_install_path)
    FS.ur_install_path = _ur_install_path
    URStatus.install_path = _ur_install_path
    FS.ur_settings_folder = Path(FS.saved_games_path, 'UniversRadio')
    URStatus.settings_folder = Path(FS.saved_games_path, 'UniversRadio')
    LOGGER.debug('UR settings folder: %s', FS.ur_settings_folder)
    FS.ur_voice_settings_file = Path(FS.ur_settings_folder, 'VoiceService.dat')
    URStatus.voice_settings_file = Path(FS.ur_settings_folder, 'VoiceService.dat')
    LOGGER.debug('UR voice service data file: %s', FS.ur_voice_settings_file)
    utils.create_simple_backup(FS.ur_voice_settings_file, file_must_exist=False)
