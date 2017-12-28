# coding=utf-8
"""
Manages commands related to ESST itself
"""
from esst import __version__, commands, core, utils

LOGGER = core.MAIN_LOGGER.getChild(__name__)


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


@utils.arg(protected=True)
def restart():
    """
    Restart ESST (protected)

    """
    if not core.CFG.restart:
        LOGGER.error('no restart command given in config')
    else:
        LOGGER.info('restarting ESST')
        core.CTX.restart = True
        core.CTX.exit = True


NAMESPACE = '!esst'
TITLE = 'Manage ESST application'
