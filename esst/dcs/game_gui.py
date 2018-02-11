# coding=utf-8
"""
Manages GameGUI hooks
"""

import elib

from esst.core import CTX, FS, MAIN_LOGGER
from esst.utils import read_template

LOGGER = MAIN_LOGGER.getChild(__name__)


# noinspection SpellCheckingInspection


def _remove_old_file():
    old_file_path = elib.path.ensure_file(FS.variant_saved_games_path, 'DCS/Scripts/ESSTGameGUI.lua', must_exist=False)

    if old_file_path.exists():
        LOGGER.debug('removing old GameGUI script')
        old_file_path.unlink()


def _install_hook():
    hook_folder = elib.path.ensure_dir(FS.variant_saved_games_path, 'Scripts/Hooks', must_exist=False, create=True)
    LOGGER.debug(f'hooks folder: {hook_folder}')
    esst_hook_path = elib.path.ensure_file(hook_folder, 'esst.lua', must_exist=False)
    LOGGER.debug(f'ESST hook path: {esst_hook_path}')
    elib.path.ensure_dir(esst_hook_path.parent, must_exist=False, create=True)
    LOGGER.debug('writing ESST hook to file')
    with open(esst_hook_path, 'w') as stream:
        stream.write(read_template('game_gui.lua'))


def install_game_gui_hooks():
    """
    Installs the GameGUI hooks in DCS Scripts folder
    """
    _remove_old_file()

    if CTX.dcs_install_hooks:
        LOGGER.debug('installing GameGUI hooks')
        _install_hook()
    else:
        LOGGER.debug('skipping installation of GameGUI hooks')
