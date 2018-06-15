# coding=utf-8
"""
Manages all FileSystem path for ESST
"""
import logging
import typing
from pathlib import Path

import elib

from esst.core.new_config import ESSTConfig

try:
    import winreg
except ImportError:
    from unittest.mock import MagicMock

    winreg = MagicMock()

LOGGER = logging.getLogger('ESST').getChild(__name__)

A_REG = winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER)


class FS:
    """
    Manages all FileSystem path for ESST
    """

    dcs_path: Path = None  # type: ignore
    dcs_exe: Path = None  # type: ignore
    dcs_autoexec_file: Path = None  # type: ignore
    dcs_hook_path: Path = None  # type: ignore
    dcs_mission_folder: Path = None  # type: ignore
    dcs_server_settings: Path = None  # type: ignore
    dcs_logs_dir: Path = None  # type: ignore

    mission_editor_lua_file: Path = None  # type: ignore

    saved_games_path: str = None  # type: ignore
    variant_saved_games_path: str = None  # type: ignore

    ur_settings_folder: str = None  # type: ignore
    ur_voice_settings_file: str = None  # type: ignore
    ur_install_path: str = None  # type: ignore

    @staticmethod
    def _reset():
        """Testing only"""
        FS.dcs_path = None
        FS.dcs_exe = None
        FS.dcs_autoexec_file = None
        FS.mission_editor_lua_file = None
        FS.saved_games_path = None
        FS.variant_saved_games_path = None
        FS.ur_install_path = None
        FS.ur_settings_folder = None
        FS.ur_install_path = None

    @staticmethod
    def ensure_path(path: typing.Union[str, Path], path_name: str, must_exist=True) -> Path:
        """
        Makes sure that "path" is a Path instance, and (optionally) exists

        Args:
            path: str or Path to check
            path_name: human friendly description of the path
            must_exist: raises FileNotFoundError if True and path does not exist

        Returns: Path instance

        """
        if path is None:
            raise RuntimeError(f'path uninitialized: {path_name}')
        return elib.path.ensure_path(path, must_exist=must_exist)

    @staticmethod
    def get_saved_games_variant(dcs_path: typing.Union[str, Path] = None) -> Path:
        """
        Infers Saved Games dir specific to this DCS installation by reading the (optional) "dcs_variant.txt"
        file that is contained at the root of the DCS installation

        Args:
            dcs_path:  path to the DCS installation

        Returns: Path instance for the Saved Games/DCS[variant] dir

        """
        if dcs_path is None:
            dcs_path = FS.ensure_path(FS.dcs_path, 'dcs path')
        FS.ensure_path(FS.saved_games_path, 'saved games')

        dcs_path_as_path = elib.path.ensure_dir(dcs_path)
        variant_path = Path(dcs_path_as_path, 'dcs_variant.txt')
        if variant_path.exists():
            variant = f'.{variant_path.read_text(encoding="utf8")}'
        else:
            variant = ''
        return elib.path.ensure_dir(FS.saved_games_path, f'DCS{variant}').absolute()

    @staticmethod
    def _get_saved_games_from_registry() -> Path:
        LOGGER.debug('searching for base "Saved Games" folder')
        try:
            LOGGER.debug('trying "User Shell Folders"')
            with winreg.OpenKey(A_REG, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders") as key:
                # noinspection SpellCheckingInspection
                base_sg = Path(winreg.QueryValueEx(key, "{4C5C32FF-BB9D-43B0-B5B4-2D72E54EAAA4}")[0])
                LOGGER.debug('found in "User Shell Folders"')
        except FileNotFoundError:
            LOGGER.debug('failed, trying "Shell Folders"')
            try:
                with winreg.OpenKey(A_REG, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders") as key:
                    # noinspection SpellCheckingInspection
                    base_sg = Path(winreg.QueryValueEx(key, "{4C5C32FF-BB9D-43B0-B5B4-2D72E54EAAA4}")[0])
                    LOGGER.debug('found in "Shell Folders"')
            except FileNotFoundError:
                LOGGER.debug('darn it, another fail, falling back to "~"')
                base_sg = Path('~').expanduser().absolute()
        return base_sg

    @staticmethod
    def discover_saved_games_path(cfg: ESSTConfig):
        """
        Tries to find Saved Games on this system

        Returns: Saved Games dir
        """
        if not cfg.saved_games_dir:
            LOGGER.debug('no Saved Games path in Config, looking it up')
            return FS._get_saved_games_from_registry()

        LOGGER.debug('Saved Games path found in Config')
        base_sg = Path(cfg.saved_games_dir)
        if not base_sg.is_dir():
            LOGGER.error(f'Saved Games dir provided in config file is invalid: {base_sg}')
            return FS._get_saved_games_from_registry()

        return base_sg


def _init_saved_games(cfg):
    FS.saved_games_path = FS.discover_saved_games_path(cfg)
    LOGGER.debug(f'Saved Games path: {FS.saved_games_path}')


def _init_dcs_path(cfg):
    FS.dcs_path = elib.path.ensure_dir(
        cfg.dcs_path
    ).absolute()
    LOGGER.debug(f'DCS path: {FS.dcs_path}')


def _init_dcs_exe():
    FS.dcs_exe = elib.path.ensure_file(
        FS.dcs_path,
        'bin/dcs.exe'
    ).absolute()
    LOGGER.debug(f'DCS exe: {FS.dcs_exe}')


def _init_saved_games_variant():
    FS.variant_saved_games_path = FS.get_saved_games_variant(
        FS.dcs_path
    ).absolute()
    LOGGER.debug(f'Saved Games variant: {FS.variant_saved_games_path}')


def _init_autoexec_cfg():
    FS.dcs_autoexec_file = Path(
        FS.variant_saved_games_path,
        'Config/autoexec.cfg'
    ).absolute()
    LOGGER.debug(f'DCS autoexec: {FS.dcs_autoexec_file}')


def _init_mission_editor_lua():
    FS.mission_editor_lua_file = elib.path.ensure_file(
        FS.dcs_path,
        'MissionEditor/MissionEditor.lua'
    ).absolute()
    LOGGER.debug(f'Mission Editor lua file: {FS.mission_editor_lua_file}')


def _init_hooks():
    FS.dcs_hook_path = elib.path.ensure_file(
        FS.variant_saved_games_path,
        'Scripts/Hooks/esst.lua',
        must_exist=False
    ).absolute()
    LOGGER.debug(f'DCS hook: {FS.dcs_hook_path}')


def _init_mission_folder():
    FS.dcs_mission_folder = elib.path.ensure_dir(
        FS.variant_saved_games_path,
        'Missions/ESST',
        must_exist=False,
        create=True
    ).absolute()
    LOGGER.debug(f'DCS mission folder: {FS.dcs_mission_folder}')


def _init_server_settings():
    FS.dcs_server_settings = elib.path.ensure_file(
        FS.variant_saved_games_path,
        'Config/serverSettings.lua',
        must_exist=False
    ).absolute()
    LOGGER.debug(f'DCS server settings: {FS.dcs_server_settings}')


def _init_logs_folder():
    FS.dcs_logs_dir = elib.path.ensure_path(
        FS.variant_saved_games_path,
        'logs',
        must_exist=False,
    ).absolute()
    LOGGER.debug(f'DCS log folder: {FS.dcs_logs_dir}')


def init_fs(cfg: ESSTConfig):
    """
    Initializes File System paths

    Args:
        cfg: ESST configuration

    """
    LOGGER.debug('init')
    _init_saved_games(cfg)
    _init_dcs_path(cfg)
    _init_dcs_exe()
    _init_saved_games_variant()
    _init_autoexec_cfg()
    _init_mission_editor_lua()
    _init_hooks()
    _init_mission_folder()
    _init_server_settings()
    _init_logs_folder()
    LOGGER.debug('FS paths initialised')
