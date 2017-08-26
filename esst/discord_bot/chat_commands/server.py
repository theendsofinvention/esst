# coding=utf-8

import argh
import humanize

from esst.core import ServerStatus
from esst.commands import DISCORD, SERVER


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


@argh.arg('--start', help='Show CPU usage in real time')
@argh.arg('--stop', help='Stop showing CPU usage in real time')
def show_cpu(
        start=False,
        stop=False
):
    """
    Show server CPU usage
    """
    if start:
        SERVER.show_cpu_usage_start()
    elif stop:
        SERVER.show_cpu_usage_stop()
    else:
        SERVER.show_cpu_usage_once()


def restart():
    """
    Restart the server computer
    """
    print('Server restart')


namespace = '!server'
title = 'Manage server computer'
