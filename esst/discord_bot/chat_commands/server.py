# coding=utf-8
"""
Commands related to managing the server computer
"""

import humanize

from esst.commands import DISCORD, SERVER
from esst.core import MAIN_LOGGER, ServerStatus
from esst.utils.conn import external_ip

from .arg import arg

LOGGER = MAIN_LOGGER.getChild(__name__)


def status():
    """
    Show current server status
    """
    output = []
    for attr_name in dir(ServerStatus):
        if attr_name.startswith('_'):
            continue
        attr_nice_name = (attr_name[:1].upper() + attr_name[1:]).replace("_", " ")
        value = getattr(ServerStatus, attr_name)
        if ('memory' in attr_name or 'swap' in attr_name) and value != 'unknown':
            value = humanize.naturalsize(value)
        if attr_name in ['cpu_usage']:
            value = str(value) + '%'
        output.append(f'{attr_nice_name}: {value}')
    DISCORD.say('Server status:\n' + '\n'.join(output))


@arg('--hours', help='Show stats for the last HOURS hours')
@arg('--minutes', help='Show stats for the last MINUTES minutes')
@arg('--days', help='Show stats for the last DAYS days')
def graph(days=0, hours=0, minutes=0):
    """
    Shows a graph of server performance (CPU, memory, ...)

    By default, the command shows the stats for the last 2 hours
    """
    if all((days==0, hours==0, minutes==0)):
        hours = 2
    SERVER.show_graph(days, hours, minutes)


@arg('--start', help='Show CPU usage in real time')
@arg('--stop', help='Stop showing CPU usage in real time')
@arg('--graphic', help='Stop showing CPU usage in real time')
def show_cpu(
        start=False,
        stop=False,
        graphic=False,
):
    """
    Show server CPU usage
    """
    if start:
        SERVER.show_cpu_usage_start()
    elif stop:
        SERVER.show_cpu_usage_stop()
    elif graphic:
        SERVER.show_cpu_graph()
    else:
        SERVER.show_cpu_usage_once()


@arg('--force', help='force server reboot, even when players are connected')
@arg(protected=True)
def reboot(force: bool = False):
    """
    Restart the server computer (protected)
    """
    LOGGER.warning('rebooting server, ciao a tutti !')
    SERVER.reboot(force)


def ip():  # pylint: disable=invalid-name
    """
    Show the server's external IP
    """
    DISCORD.say(f'Server IP: {external_ip()}')


NAMESPACE = '!server'
TITLE = 'Manage server computer'
