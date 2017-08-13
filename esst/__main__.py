# coding=utf-8
"""
Main entry point
"""

import os
import time

import blinker
import click


@click.group(invoke_without_command=True)  # noqa: C901
@click.option('--bot/--no-bot', default=True, help='Starts the Discord bot')
@click.option('--server/--no-server', default=True, help='Starts the DCS server')
@click.option('--socket/--no-socket', default=True, help='Starts the socket')
def main(bot: bool, server: bool, socket: bool):
    """
    Main entry point

    Args:
        bot: whether or not to start the Discord bot
        server: whether or not to start the DCS server
        socket: whether or not to start the DCS socket
    """
    from esst.core.logger import MAIN_LOGGER
    from esst.core.version import __version__

    MAIN_LOGGER.debug(f'starting ESST {__version__}')

    from esst.dcs import game_gui
    game_gui.install_game_gui_hooks()

    if bot:
        from esst.discord_bot import DiscordBot
        MAIN_LOGGER.debug('starting Discord bot')
        DiscordBot()
        blinker.signal('discord message').send(__name__, msg='Hello!')

    if server:
        from esst import dcs
        MAIN_LOGGER.debug('starting DCS monitoring')
        app = dcs.App()
        app.start()

    if socket:
        from esst import dcs
        MAIN_LOGGER.debug('starting socket')
        dcs.DCSListener()

    while True:
        try:
            time.sleep(0.1)
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
