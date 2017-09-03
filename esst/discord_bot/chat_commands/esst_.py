# coding=utf-8
"""
Manages commands related to ESST itself
"""

from esst.core import CFG, __version__
from esst.core.logger import log_file_path
from esst.discord_bot.commands import DISCORD
from .arg import arg


def log():
    """
    Show ESST log file
    """
    DISCORD.send(log_file_path(CFG.saved_games_dir))


def version():
    """
    Show ESST version
    """
    DISCORD.say(f'ESST v{__version__}')


@arg(protected=True)
def restart():
    """
    Restart ESST (protected)

    """
    DISCORD.say('This command is not yet implemented')


NAMESPACE = '!esst'
TITLE = 'Manage ESST application'
