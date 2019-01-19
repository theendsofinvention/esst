# coding=utf-8
"""
Commands related to managing the DSC application
"""

import humanize

from esst import commands, core, utils


def _add_regular_attr_to_output(attr_name: str,
                                attr_nice_name: str) -> str:
    try:
        attr = getattr(core.Status, attr_name)
        if hasattr(attr, 'as_str'):
            attr_as_str = attr.as_str()
            return f'{attr_nice_name}: {attr_as_str}'

        return f'{attr_nice_name}: {attr}'
    except AttributeError:
        return f'{attr_nice_name}: unknown'


def status():
    """
    Show current DCS status
    """
    output = []
    for attr_name in dir(core.Status):
        if attr_name.startswith('_'):
            continue
        attr_nice_name = attr_name[:1].upper() + attr_name[1:]
        attr_nice_name = attr_nice_name.replace("_", " ")
        if attr_name in ['mission_dict']:
            continue
        if attr_name in ['server_age']:
            output.append(f'{attr_nice_name}: '
                          f'{humanize.naturaltime(getattr(core.Status, attr_name))}')
        else:
            output.append(_add_regular_attr_to_output(attr_name, attr_nice_name))
    commands.DISCORD.say('\n'.join(output))


@utils.arg('--start', help='Show CPU usage in real time')
@utils.arg('--stop', help='Stop showing CPU usage in real time')
def show_cpu(
        start=False,
        stop=False
):
    """
    Show DCS.exe CPU usage
    """
    if start:
        commands.DCS.show_cpu_usage_start()
    elif stop:
        commands.DCS.show_cpu_usage_stop()
    else:
        commands.DCS.show_cpu_usage_once()


@utils.arg('--force', help='force restart, even when players are connected')
@utils.arg(protected=True)
def restart(force: bool = False):
    """
    Closes and restart DCS.exe (protected)
    """
    commands.DCS.restart(force=force)


def version():
    """
    Show DCS.exe version
    """
    commands.DISCORD.say(f'DCS version: {core.Status.dcs_version}')


def log():
    """
    Show DCS log file
    """
    commands.DISCORD.send_file(utils.get_dcs_log_file_path())


NAMESPACE = '!dcs'
TITLE = 'Manage DCS application'
