# coding=utf-8

from esst.core import __version__, CFG
from esst.core.logger import log_file_path
from esst.discord_bot.commands import DISCORD


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


def restart():
    """
    Restart ESST
    
    """
    DISCORD.say('This command is not yet implemented')


namespace = '!esst'
title = 'Manage ESST application'
