# coding=utf-8
"""
Manages all FileSystem path for ESST
"""
import typing

from pathlib import Path


class FS:
    """
    Manages all FileSystem path for ESST
    """

    dcs_path = None

    saved_games_path = None

    ur_settings_folder = None
    ur_voice_settings_file = None
    ur_install_path = None

    @staticmethod
    def ensure_path(path: typing.Union[str, Path], must_exist=True) -> Path:
        if path is None:
            raise RuntimeError(f'path uninitialized: {path}')
        if isinstance(path, str):
            path = Path(path)
        if must_exist and not path.exists():
            raise FileNotFoundError(path)
        return path

    @staticmethod
    def get_dcs_autoexec_file(dcs_path: typing.Union[str, Path]) -> Path:
        return FS.get_saved_games_variant(dcs_path).joinpath('Config/autoexec.cfg')

    @staticmethod
    def get_mission_editor_lua_file(dcs_path: typing.Union[str, Path]) -> Path:
        dcs_path = FS.ensure_path(dcs_path)
        path = Path(dcs_path, 'MissionEditor/MissionEditor.lua')
        return FS.ensure_path(path)

    @staticmethod
    def get_dcs_exe(dcs_path: typing.Union[str, Path]) -> Path:
        dcs_path = FS.ensure_path(dcs_path)
        dcs_exe = Path(dcs_path, 'bin/dcs.exe')
        return FS.ensure_path(dcs_exe)

    @staticmethod
    def get_saved_games_variant(dcs_path: typing.Union[str, Path]) -> Path:
        FS.ensure_path(FS.saved_games_path)
        dcs_path = FS.ensure_path(dcs_path)
        variant_path = Path(dcs_path, 'dcs_variant.txt')
        if variant_path.exists():
            variant = f'.{variant_path.read_text(encoding="utf8")}'
        else:
            variant = ''
        return FS.ensure_path(Path(FS.saved_games_path, f'DCS{variant}'))

