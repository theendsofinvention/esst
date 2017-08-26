# coding=utf-8

import argh

import humanize

from esst.commands import DISCORD, DCS
from esst.core import Status


def status():
    """
    Show current DCS status
    """
    output = []
    for attr_name in dir(Status):
        if attr_name.startswith('_'):
            continue
        attr_nice_name = attr_name[:1].upper() + attr_name[1:]
        attr_nice_name = attr_nice_name.replace("_", " ")
        if attr_name in ['mission_time', 'server_age']:
            output.append(f'{attr_nice_name}: '
                          f'{humanize.naturaltime(getattr(Status, attr_name))}')
        else:
            output.append(f'{attr_nice_name}: {getattr(Status, attr_name)}')
    DISCORD.say('\n'.join(output))


@argh.arg('--start', help='Show CPU usage in real time')
@argh.arg('--stop', help='Stop showing CPU usage in real time')
def cpu(
        start=False,
        stop=False
):
    """
    Show DCS.exe CPU usage
    """
    if start:
        DCS.show_cpu_usage_start()
    elif stop:
        DCS.show_cpu_usage_stop()
    else:
        DCS.show_cpu_usage_once()


def restart():
    """
    Closes and restart DCS.exe
    """
    DCS.restart()


def version():
    """
    Show DCS.exe version
    """
    DISCORD.say(f'DCS version: {Status.dcs_version}')


namespace = '!dcs'
title = 'Manage DCS application'
