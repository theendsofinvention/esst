# coding=utf-8
"""
Manages DCS autoexec.cfg file
"""
import pprint
import typing
from pathlib import Path

from esst import core, utils

_LOGGER = core.MAIN_LOGGER.getChild(__name__)


_SILENT_CRASH_REPORT = '''\ncrash_report_mode = "silent"\n'''


def inject_silent_crash_report(dcs_saved_games_path: typing.Union[str, Path]) -> bool:
    """
    Injects code needed for the new login method in MissionEditor.lua

    Args:
        dcs_saved_games_path: path to the Saved Games/DCS path

    Returns:
        Bool indicating success of the operation

    """
    dcs_saved_games_path = utils.ensure_path(dcs_saved_games_path)

    _LOGGER.debug(f'using Saved Games dir: {dcs_saved_games_path.absolute()}')
    if not dcs_saved_games_path.exists():
        raise FileNotFoundError('Saved games dir not found: {dcs_saved_games_path.absolute()}')

    config_dir = Path(dcs_saved_games_path, 'Config')
    _LOGGER.debug(f'config dir: {config_dir.absolute()}')
    if not config_dir.exists():
        raise FileNotFoundError(f'Config dir not found: {config_dir.absolute()}')

    autoexec_path = Path(config_dir, 'autoexec.cfg')
    _LOGGER.debug('backing up MissionEditor.lua')
    utils.create_simple_backup(autoexec_path, file_must_exist=False)

    if autoexec_path.exists():
        _LOGGER.debug('autoexec.cfg already exists, reading')
        content = autoexec_path.read_text(encoding='utf8')
    else:
        _LOGGER.debug('autoexec.cfg does not exist, creating')
        content = ''

    if _SILENT_CRASH_REPORT in content:
        _LOGGER.debug('silent crash report already enabled')
        return True

    content = f'{content}{_SILENT_CRASH_REPORT}'
    _LOGGER.debug(f'writing new "autoexec.cfg" content: {content}')
    autoexec_path.write_text(content)
    return True
