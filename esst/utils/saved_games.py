# coding=utf-8
"""
Finds Saved Games path base on registry and config
"""
from pathlib import Path

from esst.core import CFG, FS, MAIN_LOGGER

# noinspection PyProtectedMember

try:
    import winreg
except ImportError:
    from unittest.mock import MagicMock

    winreg = MagicMock()

A_REG = winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER)

LOGGER = MAIN_LOGGER.getChild(__name__)


def _get_saved_games_from_registry() -> Path:
    LOGGER.debug('searching for base "Saved Games" folder')
    try:
        LOGGER.debug('trying "User Shell Folders"')
        with winreg.OpenKey(A_REG, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders") as key:
            # noinspection SpellCheckingInspection
            base_sg = Path(winreg.QueryValueEx(key, "{4C5C32FF-BB9D-43B0-B5B4-2D72E54EAAA4}")[0])
    except FileNotFoundError:
        LOGGER.debug('failed, trying "Shell Folders"')
        try:
            with winreg.OpenKey(A_REG, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders") as key:
                # noinspection SpellCheckingInspection
                base_sg = Path(winreg.QueryValueEx(key, "{4C5C32FF-BB9D-43B0-B5B4-2D72E54EAAA4}")[0])
        except FileNotFoundError:
            LOGGER.debug('darn it, another fail, falling back to "~"')
            base_sg = Path('~').expanduser().abspath()
    return base_sg


def discover_saved_games_path():
    """
    Tries to find Saved Games on this system

    Returns: Saved Games dir
    """
    if not CFG.saved_games_dir:
        LOGGER.debug('no Saved Games path in Config, looking it up')
        base_sg = _get_saved_games_from_registry()

    else:
        LOGGER.debug('Saved Games path found in Config')
        base_sg = Path(CFG.saved_games_dir)
        if not base_sg.is_dir():
            LOGGER.error(f'Saved Games dir provided in config file is invalid: {base_sg}')
            base_sg = _get_saved_games_from_registry()

    LOGGER.debug(f'using Saved Games path: {base_sg}')
    FS.saved_games_path = base_sg
