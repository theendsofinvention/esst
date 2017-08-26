# coding=utf-8

from esst.core.version import __version__
from esst.discord_bot.commands import DISCORD


def log():
    """
    Show ESST log file
    """
    DISCORD.say('This command is not yet implemented')


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
