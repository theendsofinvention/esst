# coding=utf-8
"""
Commands related to managing the DSC application
"""

from .arg import arg
import humanize

from esst.commands import DCS, DISCORD
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


@arg('--start', help='Show CPU usage in real time')
@arg('--stop', help='Stop showing CPU usage in real time')
def show_cpu(
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


@arg('--force', help='force restart, even when players are connected')
@arg(protected=True)
def restart(force: bool = False):
    """
    Closes and restart DCS.exe (protected)
    """
    error = DCS.restart(force=force)
    if error:
        DISCORD.say(error)


def version():
    """
    Show DCS.exe version
    """
    DISCORD.say(f'DCS version: {Status.dcs_version}')


NAMESPACE = '!dcs'
TITLE = 'Manage DCS application'
