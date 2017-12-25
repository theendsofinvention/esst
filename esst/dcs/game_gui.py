# coding=utf-8
"""
Manages GameGUI hooks
"""

import os

from esst.core import CTX, FS, MAIN_LOGGER
from esst.utils import read_template

LOGGER = MAIN_LOGGER.getChild(__name__)
FILE_PATH = os.path.join(FS.saved_games_path, 'DCS/Scripts/ESSTGameGUI.lua')


# noinspection SpellCheckingInspection


def install_game_gui_hooks():
    """
    Installs the GameGUI hooks in DCS Scripts folder
    """

    if CTX.dcs_install_hooks:
        LOGGER.debug('installing GameGUI hooks')
        with open(FILE_PATH, 'w') as stream:
            stream.write(read_template('game_gui.lua'))
    else:
        LOGGER.debug('skipping installation of GameGUI hooks')
