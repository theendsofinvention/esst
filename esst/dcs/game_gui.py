# coding=utf-8
"""
Manages GameGUI hooks
"""

import elib
from esst.core import CTX, FS, MAIN_LOGGER
from esst.utils import read_template

LOGGER = MAIN_LOGGER.getChild(__name__)
OLD_FILE_PATH = elib.path.ensure_file(FS.saved_games_path, 'DCS/Scripts/ESSTGameGUI.lua', must_exist=False)
FILE_PATH = elib.path.ensure_file(FS.saved_games_path, 'DCS/Scripts/Hooks/esst.lua', must_exist=False)


# noinspection SpellCheckingInspection


def install_game_gui_hooks():
    """
    Installs the GameGUI hooks in DCS Scripts folder
    """

    if OLD_FILE_PATH.exists():
        LOGGER.debug('removing old GameGUI script')
        OLD_FILE_PATH.unlink()

    if CTX.dcs_install_hooks:
        elib.path.ensure_dir(FILE_PATH.parent, must_exist=False, create=True)
        LOGGER.debug('installing GameGUI hooks')
        with open(FILE_PATH, 'w') as stream:
            stream.write(read_template('game_gui.lua'))
    else:
        LOGGER.debug('skipping installation of GameGUI hooks')
