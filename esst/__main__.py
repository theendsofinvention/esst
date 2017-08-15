# coding=utf-8
"""
Main entry point
"""

import os
import time

import blinker
import click


@click.group(invoke_without_command=True)  # noqa: C901
@click.pass_context
@click.option('--bot/--no-bot', default=True, help='Starts the Discord bot', show_default=True)
@click.option('--server/--no-server', default=True, help='Starts the DCS app', show_default=True)
@click.option('--socket/--no-socket', default=True, help='Starts the socket', show_default=True)
@click.option('--start-dcs/--no-start-dcs', help='Spawn DCS.exe process', default=True, show_default=True)
@click.option('--install-hooks/--no-install-hooks', help='Install GameGUI hooks', default=True, show_default=True)
@click.option('--install-dedi-config/--no-install-dedi-config', help='Setup DCS to run in dedicated mode', default=True,
              show_default=True)
@click.option('--auto-mission/--no-auto-mission', help='Download latest mission', default=True, show_default=True)
def main(ctx,
         bot: bool,
         server: bool,
         socket: bool,
         start_dcs: bool,
         install_hooks: bool,
         install_dedi_config: bool,
         auto_mission: bool,
         ):
    """
    Main entry point

    Args:
        ctx: click context
        bot: whether or not to start the Discord bot
        server: whether or not to start the DCS server
        socket: whether or not to start the DCS socket
        start_dcs: start the server thread, but not the actual DCS app
        hooks: install GemGUI hooks
        dedi_config: setup DCS to run in dedicated mode
        auto_mission: downloads the latest mission from Github
    """
    from esst.core.logger import MAIN_LOGGER
    from esst.core.version import __version__

    ctx.obj = {
        'dcs_start_ok': start_dcs,
        'dcs_show_cpu_usage': False,
        'dcs_show_cpu_usage_once': False,
        'dcs_kill': False,
        'dcs_restart': False,
        'threads': {
            'dcs': {
                'ready_to_exit': True,
                'should_exit': False,
            },
            'socket': {
                'ready_to_exit': True,
                'should_exit': False,
            },
            'discord': {
                'ready_to_exit': True,
                'should_exit': False,
            },
        }
    }

    import ctypes
    ctypes.windll.kernel32.SetConsoleTitleW(f'ESST v{__version__} - Use CTRL+C to exit')
    try:
        MAIN_LOGGER.debug(f'starting ESST {__version__}')

        from esst import discord_bot
        discord_bot.DiscordBot(ctx)

        from esst import dcs
        dcs.App(ctx)
        dcs.DCSListener(ctx)

        while True:
            time.sleep(0.5)

    except KeyboardInterrupt:

        MAIN_LOGGER.info('ESST has been interrupted by user request, closing all threads')

        def _exit_gracefully2(thread_name):
            ctx.obj['threads'][thread_name]['should_exit'] = True
            now = time.time()
            while not ctx.obj['threads'][thread_name]['ready_to_exit']:
                if time.time() > now + 20:
                    MAIN_LOGGER.error(f'{thread_name} thread did not exit gracefully')
                    break
                time.sleep(0.1)

        _exit_gracefully2('dcs')
        _exit_gracefully2('discord')
        _exit_gracefully2('socket')

        # noinspection PyProtectedMember
        os._exit(0)  # pylint: disable=protected-access


if __name__ == '__main__':
    main()  # pylint: disable=no-value-for-parameter
