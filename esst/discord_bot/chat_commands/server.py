# coding=utf-8
"""
Commands related to managing the server computer
"""

import humanize

from esst import LOGGER, commands, core, utils


def status():
    """
    Show current server status
    """
    output = []
    for attr_name in dir(core.ServerStatus):
        if attr_name.startswith('_'):
            continue
        attr_nice_name = (attr_name[:1].upper() +
                          attr_name[1:]).replace("_", " ")
        value = getattr(core.ServerStatus, attr_name)
        if ('memory' in attr_name or 'swap' in attr_name) and value != 'unknown':
            value = humanize.naturalsize(value)
        if 'usage' in attr_name:
            value = str(value) + '%'
        output.append(f'{attr_nice_name}: {value}')
    commands.DISCORD.say('Server status:\n' + '\n'.join(output))


@utils.arg('--hours', help='Show stats for the last HOURS hours')
@utils.arg('--minutes', help='Show stats for the last MINUTES minutes')
@utils.arg('--days', help='Show stats for the last DAYS days')
def graph(days=0, hours=0, minutes=0):
    """
    Shows a graph of server performance (CPU, memory, ...)

    By default, the command shows the stats for the last 2 hours
    """
    if all((days == 0, hours == 0, minutes == 0)):
        hours = 2
    commands.SERVER.show_graph(days, hours, minutes)


@utils.arg('--start', help='Show CPU usage in real time')
@utils.arg('--stop', help='Stop showing CPU usage in real time')
def show_cpu(
        start=False,
        stop=False,
):
    """
    Show server CPU usage
    """
    if start:
        commands.SERVER.show_cpu_usage_start()
    elif stop:
        commands.SERVER.show_cpu_usage_stop()
    else:
        commands.SERVER.show_cpu_usage_once()


@utils.arg('--force', help='force server reboot, even when players are connected')
@utils.arg(protected=True)
def reboot(force: bool = False):
    """
    Restart the server computer (protected)
    """
    LOGGER.warning('rebooting server, ciao a tutti !')
    commands.SERVER.reboot(force)


def ip():  # pylint: disable=invalid-name
    """
    Show the server's external IP
    """
    commands.DISCORD.say(f'Server IP: {utils.external_ip()}')


NAMESPACE = '!server'
TITLE = 'Manage server computer'
