# coding=utf-8
"""
Manages DCS autoexec.cfg file
"""

from esst import FS, LOGGER, utils

_SILENT_CRASH_REPORT = '''\ncrash_report_mode = "silent"\n'''


def inject_silent_crash_report() -> bool:
    """
    Injects code needed for the new login method in MissionEditor.lua

    :return: success of the operation
    :rtype: bool
    """

    FS.ensure_path(FS.saved_games_path, 'saved games')
    autoexec_path = FS.ensure_path(FS.dcs_autoexec_file, 'dcs autoexec file', must_exist=False)
    utils.create_versioned_backup(autoexec_path, file_must_exist=False)

    if autoexec_path.exists():
        LOGGER.debug('autoexec.cfg already exists, reading')
        content = autoexec_path.read_text(encoding='utf8')
    else:
        LOGGER.debug('autoexec.cfg does not exist, creating')
        content = ''

    if _SILENT_CRASH_REPORT in content:
        LOGGER.debug('silent crash report already enabled')
        return True

    content = f'{content}{_SILENT_CRASH_REPORT}'
    LOGGER.debug('writing new "autoexec.cfg" content: %s', content)
    autoexec_path.write_text(content)
    return True
