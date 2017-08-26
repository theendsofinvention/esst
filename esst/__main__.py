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


async def force_exit_FUCK():
    while len(asyncio.Task.all_tasks()) > 1:
        tasks = asyncio.Task.all_tasks()
        for task in list(tasks):
            if 'finished' in repr(task):
                print(f'popping {task}')
                tasks.remove(task)
            if 'cancelled' in repr(task):
                print(f'popping {task}')
                tasks.remove(task)
            if 'force_exit' in repr(task):
                print(f'popping {task}')
                tasks.remove(task)
        if tasks:
            MAIN_LOGGER.debug(f'waiting on tasks:\n{tasks}')
            print(f'waiting on tasks:\n{tasks}')
            await asyncio.sleep(1)
        else:
            break


async def async_force_exit():
    for task in asyncio.Task.all_tasks():
        MAIN_LOGGER.warning(f'dangling tasks: {task}')
    raise SystemExit(0)


def force_exit():
    for task in asyncio.Task.all_tasks():
        if 'finished' in repr(task):
            continue
        if 'cancelled' in repr(task):
            continue
        if 'force_exit' in repr(task):
            continue
        MAIN_LOGGER.warning(f'dangling tasks: {task}')
    raise SystemExit(0)


@click.group(invoke_without_command=True)  # noqa: C901
@click.option('--bot/--no-bot', default=True, help='Starts the Discord bot', show_default=True)
@click.option('--server/--no-server', default=True, help='Starts the DCS app', show_default=True)
@click.option('--listener/--no-listener', default=True, help='Starts the socket', show_default=True)
@click.option('--start-dcs/--no-start-dcs', help='Spawn DCS.exe process', default=True, show_default=True)
@click.option('--install-hooks/--no-install-hooks', help='Install GameGUI hooks', default=True, show_default=True)
@click.option('--install-dedi-config/--no-install-dedi-config', help='Setup DCS to run in dedicated mode', default=True,
              show_default=True)
@click.option('--auto-mission/--no-auto-mission', help='Download latest mission', default=True, show_default=True)
def main(bot: bool,
         server: bool,
         listener: bool,
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
        listener: whether or not to start the DCS socket
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
    CTX.socket_start = listener and CFG.start_listener
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

    from esst.listener import DCSListener
    try:
        listener = DCSListener()
    except OSError as exc:
        if exc.errno == 10048:
            MAIN_LOGGER.error('cannot bind socket, maybe another instance of ESST is already running?')
            exit(-1)

    CTX.loop.create_task(bot.run())
    CTX.loop.create_task(app.run())
    CTX.loop.create_task(listener.run())
    CTX.loop.create_task(watch_for_exceptions())

    def sigint_handler(signal, frame):
        MAIN_LOGGER.info('ESST has been interrupted by user request, shutting down')
        CTX.exit = True

        asyncio.ensure_future(app.exit(), loop=CTX.loop)
        asyncio.ensure_future(listener.exit(), loop=CTX.loop)
        asyncio.ensure_future(bot.exit(), loop=CTX.loop)

        CTX.loop.call_later(5, force_exit)

    import signal
    signal.signal(signal.SIGINT, sigint_handler)
    CTX.loop.run_forever()
