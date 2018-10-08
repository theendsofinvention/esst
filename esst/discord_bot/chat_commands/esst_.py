# coding=utf-8
"""
Manages commands related to ESST itself
"""

from esst import __version__, commands, utils


def log():
    """
    Show ESST log file
    """
    commands.DISCORD.send_file('esst.log')


def changelog():
    """
    Show ESST changelog file
    """
    changelog_path = utils.get_esst_changelog_path()
    if changelog_path:
        commands.DISCORD.send_file(changelog_path)


def version():
    """
    Show ESST version
    """
    commands.DISCORD.say(f'ESST v{__version__}')


NAMESPACE = '!esst'
TITLE = 'Manage ESST application'
