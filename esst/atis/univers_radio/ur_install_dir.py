# coding=utf-8
"""
MAnages UR installation path
"""
import typing
from pathlib import Path

from esst.core import CFG, MAIN_LOGGER

try:
    import winreg
except ImportError:
    from unittest.mock import MagicMock

    winreg = MagicMock()

A_REG = winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER)

LOGGER = MAIN_LOGGER.getChild(__name__)


def _get_ur_install_path_from_registry() -> typing.Union[Path, None]:
    LOGGER.debug('searching for base "Saved Games" folder')
    try:
        with winreg.OpenKey(A_REG, r"Software\sSoft\UniversRadio") as key:
            # noinspection SpellCheckingInspection
            return Path(winreg.QueryValueEx(key, "Install_Dir")[0])
    except FileNotFoundError:
        return None


def discover_ur_install_path() -> Path:
    """
    Tries to find Saved Games on this system

    Returns: Saved Games dir
    """
    if not CFG.ur_path:
        LOGGER.debug('no UR install path in Config, looking it up')
        _ur_install_path = _get_ur_install_path_from_registry()

    else:
        LOGGER.debug('UR install path found in Config')
        _ur_install_path = Path(CFG.saved_games_dir)
        if not _ur_install_path.is_dir():
            LOGGER.error(f'UR install path provided in config file is invalid: {_ur_install_path}')
            _ur_install_path = _get_ur_install_path_from_registry()

    LOGGER.debug(f'using Saved Games path: {_ur_install_path}')
    return _ur_install_path


UR_INSTALL_PATH = discover_ur_install_path()
