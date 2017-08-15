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
@click.option('--hooks/--no-hooks', help='Install GameGUI hooks', default=True, show_default=True)
@click.option('--dedi-config/--no-dedi-config', help='Setup DCS to run in dedicated mode', default=True,
              show_default=True)
@click.option('--auto-mission/--no-auto-mission', help='Download latest mission', default=True, show_default=True)
def main(ctx,
         bot: bool,
         server: bool,
         socket: bool,
         start_dcs: bool,
         hooks: bool,
         dedi_config: bool,
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
        'start_dcs': start_dcs
    }

    import ctypes
    ctypes.windll.kernel32.SetConsoleTitleW(f'ESST v{__version__} - Use CTRL+C to exit')
    try:
        MAIN_LOGGER.debug(f'starting ESST {__version__}')

        if auto_mission:
            from esst.dcs.missions_manager import get_latest_mission_from_github
            get_latest_mission_from_github(ctx)

        if hooks:
            from esst.dcs.game_gui import install_game_gui_hooks
            install_game_gui_hooks(ctx)

        if bot:
            from esst import discord_bot
            MAIN_LOGGER.debug('starting Discord bot')
            discord_bot.DiscordBot(ctx)

        if server:
            from esst import dcs
            MAIN_LOGGER.debug('starting DCS monitoring')
            dcs.App(ctx)

        if socket:
            from esst import dcs
            MAIN_LOGGER.debug('starting socket')
            dcs.DCSListener(ctx)

        while True:
            time.sleep(0.5)

    except KeyboardInterrupt:

        MAIN_LOGGER.info('ESST has been interrupted by user request, closing all threads')

        def _exit_gracefully(thread_name):
            ready_to_exit = False

            def _ready_to_exit(*_):
                nonlocal ready_to_exit
                MAIN_LOGGER.debug(f'{thread_name} is ready to exit')
                ready_to_exit = True

            blinker.signal(f'{thread_name} ready to exit').connect(_ready_to_exit)
            blinker.signal(f'{thread_name} command').send(__name__, cmd='exit')

            now = time.time()
            while not ready_to_exit:
                if time.time() > now + 20:
                    MAIN_LOGGER.error(f'{thread_name} thread did not exit gracefully')
                    break
                time.sleep(0.1)

        if server:
            _exit_gracefully('dcs')

        if bot:
            _exit_gracefully('discord')

        if socket:
            _exit_gracefully('socket')

        # noinspection PyProtectedMember
        os._exit(0)  # pylint: disable=protected-access


if __name__ == '__main__':
    main()  # pylint: disable=no-value-for-parameter
