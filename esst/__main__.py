# coding=utf-8
"""
Main entry point
"""
import asyncio
import queue

import click
import elib

from esst import __version__
from esst.core import CFG, CTX, MAIN_LOGGER, fs_paths

MAIN_LOGGER.debug('Starting ESST version %s', __version__)


async def watch_for_exceptions():
    """
    Dummy loop to wake up asyncio event loop from time to time
    """
    while True:
        if CTX.exit:
            break
        await asyncio.sleep(0.1)


def _setup_logging():
    if CFG.debug:
        elib.custom_logging.set_handler_level('ESST', 'ch', 'debug')


def _setup_sentry():
    if CFG.sentry_dsn:
        from esst.utils.sentry import Sentry
        CTX.sentry = Sentry(CFG.sentry_dsn)
        CTX.sentry.register_context('App context', CTX)
        CTX.sentry.register_context('Config', CFG)


# pylint: disable=too-many-locals,too-many-arguments
@click.group(invoke_without_command=True)  # noqa: C901
@click.option('--discord/--no-discord', default=True, help='Starts the Discord bot loop', show_default=True)
@click.option('--server/--no-server', default=True, help='Starts the server monitoring loop', show_default=True)
@click.option('--dcs/--no-dcs', default=True, help='Starts the DCS app loop', show_default=True)
@click.option('--listener/--no-listener', default=True, help='Starts the socket loop', show_default=True)
@click.option('--start-dcs/--no-start-dcs', help='Spawn DCS.exe process', default=True, show_default=True)
@click.option('--install-hooks/--no-install-hooks', help='Install GameGUI hooks', default=True, show_default=True)
@click.option('--install-dedi-config/--no-install-dedi-config', help='Setup DCS to run in dedicated mode', default=True,
              show_default=True)
@click.option('--auto-mission/--no-auto-mission', help='Download latest mission', default=True, show_default=True)
def main(
        discord: bool,
        server: bool,
        dcs: bool,
        listener: bool,
        start_dcs: bool,
        install_hooks: bool,
        install_dedi_config: bool,
        auto_mission: bool, ):
    """
    Main entry point

    Args:
        install_dedi_config: setup DCS to run in dedicated mode
        install_hooks: install GameGUI hooks
        dcs: start dcs loop
        discord: start Discord bot loop
        server: start server loop
        listener: start the listener loop
        start_dcs: start the server thread, but not the actual DCS app
        auto_mission: downloads the latest mission from Github
    """
    _setup_logging()

    _setup_sentry()

    loop = asyncio.get_event_loop()
    CTX.loop = loop

    import esst.wan
    CTX.wan = loop.run_until_complete(esst.wan.wan_available())
    loop.create_task(esst.wan.monitor_connection())

    CTX.start_discord_loop = discord and CFG.start_discord_loop
    CTX.start_server_loop = server and CFG.start_server_loop
    CTX.start_dcs_loop = dcs and CFG.start_dcs_loop
    CTX.start_listener_loop = listener and CFG.start_listener_loop

    if not (start_dcs and CFG.dcs_can_start):
        CTX.dcs_blocker.append('config')

    CTX.dcs_setup_dedi_config = install_dedi_config
    CTX.dcs_install_hooks = install_hooks
    CTX.dcs_auto_mission = auto_mission

    loop = asyncio.get_event_loop()
    # loop.set_debug(True)
    CTX.discord_msg_queue = queue.Queue()

    import ctypes
    ctypes.windll.kernel32.SetConsoleTitleW('ESST v%s - Use CTRL+C to exit', __version__)
    MAIN_LOGGER.debug('starting ESST %s', __version__)

    fs_paths.init_fs(CFG)

    from esst.utils import clean_all_folder, assign_ports
    clean_all_folder()
    assign_ports()

    from esst import atis
    atis.init_module()

    import esst.discord_bot.discord_bot
    discord_loop = esst.discord_bot.discord_bot.App()

    import esst.dcs

    dcs_loop = esst.dcs.dcs.App()

    import esst.server.server
    server_loop = esst.server.server.App()

    from esst.listener import DCSListener
    listener_loop = DCSListener()

    futures = asyncio.gather(
        loop.create_task(discord_loop.run()),
        loop.create_task(dcs_loop.run()),
        loop.create_task(listener_loop.run()),
        loop.create_task(server_loop.run()),
        loop.create_task(watch_for_exceptions()),
    )

    def sigint_handler(*_):
        """
        Catches exit signal (triggered byu CTRL+C)

        Args:
            *_: frame

        """
        MAIN_LOGGER.info(
            'ESST has been interrupted by user request, shutting down')
        CTX.exit = True

    import signal
    signal.signal(signal.SIGINT, sigint_handler)
    loop.run_until_complete(futures)
    MAIN_LOGGER.debug('main loop is done, killing DCS')

    futures = asyncio.gather(  # type: ignore
        loop.create_task(dcs_loop.kill_running_app()),
        loop.create_task(listener_loop.run_until_dcs_is_closed()),
    )

    loop.run_until_complete(futures)

    MAIN_LOGGER.debug('all done !')


if __name__ == '__main__':
    main()  # pylint: disable=no-value-for-parameter
