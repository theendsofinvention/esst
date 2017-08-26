# coding=utf-8
"""
Main entry point
"""

import asyncio
import queue

import click

from esst.core import CTX, MAIN_LOGGER


async def watch_for_exceptions():
    while True:
        if CTX.exit:
            break
        await asyncio.sleep(0.1)

def force_exit():
    for task in asyncio.Task.all_tasks():
        MAIN_LOGGER.warning(f'dangling tasks: {task}')
    raise SystemExit(0)


@click.group(invoke_without_command=True)  # noqa: C901
@click.option('--bot/--no-bot', default=True, help='Starts the Discord bot', show_default=True)
@click.option('--server/--no-server', default=True, help='Starts the DCS app', show_default=True)
@click.option('--socket/--no-socket', default=True, help='Starts the socket', show_default=True)
@click.option('--start-dcs/--no-start-dcs', help='Spawn DCS.exe process', default=True, show_default=True)
@click.option('--install-hooks/--no-install-hooks', help='Install GameGUI hooks', default=True, show_default=True)
@click.option('--install-dedi-config/--no-install-dedi-config', help='Setup DCS to run in dedicated mode', default=True,
              show_default=True)
@click.option('--auto-mission/--no-auto-mission', help='Download latest mission', default=True, show_default=True)
def main(bot: bool,
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
        install_dedi_config: setup DCS to run in dedicated mode
        install_hooks: install GemGUI hooks
        ctx: click context
        bot: whether or not to start the Discord bot
        server: whether or not to start the DCS server
        socket: whether or not to start the DCS socket
        start_dcs: start the server thread, but not the actual DCS app
        auto_mission: downloads the latest mission from Github
    """

    from esst.core import CTX, MAIN_LOGGER, __version__, CFG

    if CFG.sentry_dsn:
        from esst.utils.sentry import Sentry
        sentry = Sentry(CFG.sentry_dsn)
        sentry.register_context('App context', CTX)
        sentry.register_context('Config', CFG)

    CTX.loop = asyncio.get_event_loop()
    CTX.discord_start_bot = bot and CFG.start_bot
    CTX.dcs_start = server and CFG.start_server
    CTX.dcs_can_start = start_dcs
    CTX.socket_start = socket and CFG.start_socket
    CTX.dcs_setup_dedi_config = install_dedi_config
    CTX.dcs_install_hooks = install_hooks
    CTX.dcs_auto_mission = auto_mission

    CTX.loop = asyncio.get_event_loop()
    # CTX.loop.set_debug(True)
    CTX.discord_msg_queue = queue.Queue()

    import ctypes
    ctypes.windll.kernel32.SetConsoleTitleW(f'ESST v{__version__} - Use CTRL+C to exit')
    MAIN_LOGGER.debug(f'starting ESST {__version__}')

    from esst import discord_bot
    bot = discord_bot.DiscordBot()

    from esst.dcs import dcs
    app = dcs.App()

    from esst import listener
    try:
        socket = listener.DCSListener()
    except OSError as exc:
        if exc.errno == 10048:
            MAIN_LOGGER.error('cannot bind socket, maybe another instance of ESST is already running?')
            exit(-1)


    CTX.loop.create_task(bot.run())
    CTX.loop.create_task(app.run())
    CTX.loop.create_task(socket.run())
    CTX.loop.create_task(watch_for_exceptions())

    def sigint_handler(signal, frame):

        CTX.exit = True
        # asyncio.ensure_future(bot.exit(), loop=CTX.loop)
        # asyncio.ensure_future(socket.exit(), loop=CTX.loop)
        # asyncio.ensure_future(app.exit(), loop=CTX.loop)
        CTX.loop.create_task(bot.exit())
        CTX.loop.create_task(socket.exit())
        CTX.loop.create_task(app.exit())

        # CTX.loop.stop()
        #
        # import time
        # MAIN_LOGGER.debug('WAITING FOR LOOP TO CLOSE')
        # while CTX.loop.is_running():
        #     time.sleep(0.1)

        # CTX.loop.run_until_complete(app.exit())
        # CTX.loop.run_until_complete(socket.exit())
        # CTX.loop.run_until_complete(bot.exit())

        CTX.loop.call_later(5, force_exit)
        # CTX.loop.run_until_complete(asyncio.gather(*asyncio.Task.all_tasks()))


    import signal
    signal.signal(signal.SIGINT, sigint_handler)
    CTX.loop.run_forever()

    # try:
    #     CTX.loop.run_forever()
    #
    # except KeyboardInterrupt:
    #
    #     MAIN_LOGGER.info('ESST has been interrupted by user request, closing all threads')
    #
    #     CTX.exit = True
    #
    #     CTX.loop.run_until_complete(app.exit())
    #     CTX.loop.run_until_complete(socket.exit())
    #     CTX.loop.run_until_complete(bot.exit())
    #
    #     CTX.loop.call_later(5, force_exit)
    #     CTX.loop.run_until_complete(asyncio.gather(*asyncio.Task.all_tasks()))
    #     # CTX.loop.run_forever()
    #     # asyncio.wait(asyncio.gather(*asyncio.Task.all_tasks()), timeout=5)
    #
    # finally:
    #     CTX.loop.close()
