# coding=utf-8
"""
Manages DCS autoexec.cfg file
"""

from esst import core, utils

_LOGGER = core.MAIN_LOGGER.getChild(__name__)

_SILENT_CRASH_REPORT = '''\ncrash_report_mode = "silent"\n'''


def inject_silent_crash_report() -> bool:
    """
    Injects code needed for the new login method in MissionEditor.lua

    Args:
        dcs_path: path to the installation of DCS

    Returns:
        Bool indicating success of the operation

    """

    core.FS.ensure_path(core.FS.saved_games_path, 'saved games')
    autoexec_path = core.FS.ensure_path(core.FS.dcs_autoexec_file, 'dcs autoexec file', must_exist=False)
    utils.create_versioned_backup(autoexec_path, file_must_exist=False)

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
