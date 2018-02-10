# coding=utf-8
"""
Manages GameGUI hooks
"""

import elib

from esst.core import CTX, FS, MAIN_LOGGER
from esst.utils import read_template

LOGGER = MAIN_LOGGER.getChild(__name__)


# noinspection SpellCheckingInspection


def install_game_gui_hooks():
    """
    Installs the GameGUI hooks in DCS Scripts folder
    """
    old_file_path = elib.path.ensure_file(FS.variant_saved_games_path, 'DCS/Scripts/ESSTGameGUI.lua', must_exist=False)

    hook_folder = elib.path.ensure_dir(FS.variant_saved_games_path, 'Scripts/Hooks', must_exist=False, create=True)
    file_path = elib.path.ensure_file(hook_folder, 'esst.lua', must_exist=False)

    if old_file_path.exists():
        LOGGER.debug('removing old GameGUI script')
        old_file_path.unlink()

    if CTX.dcs_install_hooks:
        elib.path.ensure_dir(file_path.parent, must_exist=False, create=True)
        LOGGER.debug('installing GameGUI hooks')
        with open(file_path, 'w') as stream:
            stream.write(read_template('game_gui.lua'))
    else:
        LOGGER.debug('skipping installation of GameGUI hooks')
