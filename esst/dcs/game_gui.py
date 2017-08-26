# coding=utf-8
"""
Manages GameGUI hooks
"""

import os
import pkg_resources

from esst.core import CFG, CTX, MAIN_LOGGER
from esst.utils import read_template
from esst.core.context import Context

LOGGER = MAIN_LOGGER.getChild(__name__)
FILE_PATH = os.path.join(CFG.saved_games_dir, 'Scripts/ESSTGameGUI.lua')

# noinspection SpellCheckingInspection
GAMEGUI_CONTENT_PATH = os.path.join(os.path.dirname(__file__), 'game_gui.template')
if not os.path.exists(GAMEGUI_CONTENT_PATH):
    GAMEGUI_CONTENT_PATH = pkg_resources.resource_filename('esst', '/dcs/game_gui.template')
if not os.path.exists(GAMEGUI_CONTENT_PATH):
    raise FileNotFoundError(GAMEGUI_CONTENT_PATH)
with open(GAMEGUI_CONTENT_PATH) as handle:
    GAMEGUI_CONTENT = handle.read()


def install_game_gui_hooks():
    """
    Installs the GameGUI hooks in DCS Scripts folder
    """
    if CTX.dcs_install_hooks:
        LOGGER.debug('installing GameGUI hooks')
        with open(FILE_PATH, 'w') as handle:
            handle.write(GAMEGUI_CONTENT)
    else:
        LOGGER.debug('skipping installation of GameGUI hooks')
