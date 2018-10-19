# coding=utf-8
"""
Manages all FileSystem path for ESST
"""
import typing
import winreg
from pathlib import Path

from esst import LOGGER
from esst.utils import check_dir, check_file, check_path

A_REG = winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER)


class FS:
    """
    Manages all FileSystem path for ESST
    """

    dcs_path: typing.Optional[Path] = None
    dcs_exe: typing.Optional[Path] = None
    dcs_autoexec_file: typing.Optional[Path] = None
    dcs_hook_path: typing.Optional[Path] = None
    dcs_mission_folder: typing.Optional[Path] = None
    dcs_server_settings: typing.Optional[Path] = None
    dcs_logs_dir: typing.Optional[Path] = None

    mission_editor_lua_file: typing.Optional[Path] = None

    saved_games_path: typing.Optional[str] = None
    variant_saved_games_path: typing.Optional[str] = None

    ur_settings_folder: typing.Optional[str] = None
    ur_voice_settings_file: typing.Optional[Path] = None
    ur_install_path: typing.Optional[str] = None

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
    def ensure_path(path: typing.Optional[typing.Union[str, Path]], path_name: str, must_exist=True) -> Path:
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
        return check_path(path, must_exist=must_exist)

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
        saved_games_path = FS.ensure_path(FS.saved_games_path, 'saved games')

        dcs_path_as_path = check_dir(dcs_path)
        variant_path = Path(dcs_path_as_path, 'dcs_variant.txt')
        if variant_path.exists():
            variant = f'.{variant_path.read_text(encoding="utf8")}'
        else:
            variant = ''
        return check_dir(saved_games_path, f'DCS{variant}')

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
    def discover_saved_games_path():
        """
        Tries to find Saved Games on this system

        Returns: Saved Games dir
        """
        from esst import ESSTConfig
        if not ESSTConfig.SAVED_GAMES_DIR():
            LOGGER.debug('no Saved Games path in Config, looking it up')
            return FS._get_saved_games_from_registry()

        LOGGER.debug('Saved Games path found in Config')
        base_sg = Path(ESSTConfig.SAVED_GAMES_DIR())
        if not base_sg.is_dir():
            LOGGER.error('Saved Games dir provided in config file is invalid:  %s', base_sg)
            return FS._get_saved_games_from_registry()

        return base_sg

    @staticmethod
    def _init_saved_games():
        FS.saved_games_path = FS.discover_saved_games_path()
        LOGGER.debug('Saved Games path:  %s', FS.saved_games_path)

    @staticmethod
    def _init_dcs_path():
        from esst import DCSConfig
        FS.dcs_path = check_dir(DCSConfig.DCS_PATH())
        LOGGER.debug('DCS path:  %s', FS.dcs_path)

    @staticmethod
    def _init_dcs_exe():
        FS.dcs_exe = check_file(FS.dcs_path, 'bin/dcs.exe')
        LOGGER.debug('DCS exe:  %s', FS.dcs_exe)

    @staticmethod
    def _init_saved_games_variant():
        FS.variant_saved_games_path = FS.get_saved_games_variant(FS.dcs_path)
        LOGGER.debug('Saved Games variant:  %s', FS.variant_saved_games_path)

    @staticmethod
    def _init_autoexec_cfg():
        FS.dcs_autoexec_file = Path(FS.variant_saved_games_path, 'Config/autoexec.cfg')
        LOGGER.debug('DCS autoexec: %s', FS.dcs_autoexec_file)

    @staticmethod
    def _init_mission_editor_lua():
        FS.mission_editor_lua_file = check_file(FS.dcs_path, 'MissionEditor/MissionEditor.lua')
        LOGGER.debug('Mission Editor lua file: %s', FS.mission_editor_lua_file)

    @staticmethod
    def _init_hooks():
        FS.dcs_hook_path = check_file(FS.variant_saved_games_path, 'Scripts/Hooks/esst.lua', must_exist=False)
        LOGGER.debug('DCS hook: %s', FS.dcs_hook_path)

    @staticmethod
    def _init_mission_folder():
        FS.dcs_mission_folder = check_dir(FS.variant_saved_games_path, 'Missions/ESST', must_exist=False, create=True)
        LOGGER.debug('DCS mission folder: %s', FS.dcs_mission_folder)

    @staticmethod
    def _init_server_settings():
        FS.dcs_server_settings = check_file(FS.variant_saved_games_path, 'Config/serverSettings.lua', must_exist=False)
        LOGGER.debug('DCS server settings: %s', FS.dcs_server_settings)

    @staticmethod
    def _init_logs_folder():
        FS.dcs_logs_dir = check_path(FS.variant_saved_games_path, 'logs', must_exist=False)
        LOGGER.debug('DCS log folder: %s', FS.dcs_logs_dir)

    @staticmethod
    def init():
        """
        Initializes File System paths
        """
        LOGGER.debug('init')
        FS._init_saved_games()
        FS._init_dcs_path()
        FS._init_dcs_exe()
        FS._init_saved_games_variant()
        FS._init_autoexec_cfg()
        FS._init_mission_editor_lua()
        FS._init_hooks()
        FS._init_mission_folder()
        FS._init_server_settings()
        FS._init_logs_folder()
        LOGGER.debug('FS paths initialised')
