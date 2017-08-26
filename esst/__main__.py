# coding=utf-8
"""
Main entry point
"""

import asyncio
import queue

import click

from esst.core.context import Context


async def watch_for_exceptions(ctx: Context):
    while True:
        if ctx.exit:
            break
        await asyncio.sleep(0.1)


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
        install_dedi_config: setup DCS to run in dedicated mode
        install_hooks: install GemGUI hooks
        ctx: click context
        bot: whether or not to start the Discord bot
        server: whether or not to start the DCS server
        socket: whether or not to start the DCS socket
        start_dcs: start the server thread, but not the actual DCS app
        auto_mission: downloads the latest mission from Github
    """
    from esst import discord_args
    discord_args.main()
    return

    from esst.core.logger import MAIN_LOGGER
    from esst.core.version import __version__

    from esst.core.context import Context
    ctx = Context()

    from esst.core.config import CFG
    if CFG.sentry_dsn:
        from esst.core.sentry import Sentry
        sentry = Sentry(CFG.sentry_dsn)
        sentry.register_context('App context', ctx)
        sentry.register_context('Config', CFG)

    ctx.loop = asyncio.get_event_loop()
    ctx.discord_start_bot = bot
    ctx.dcs_start = server
    ctx.dcs_can_start = start_dcs
    ctx.socket_start = socket
    ctx.dcs_setup_dedi_config = install_dedi_config
    ctx.dcs_install_hooks = install_hooks
    ctx.dcs_auto_mission = auto_mission
    ctx.click_context = ctx

    ctx.loop = asyncio.get_event_loop()
    ctx.discord_msg_queue = queue.Queue()

    import ctypes
    ctypes.windll.kernel32.SetConsoleTitleW(f'ESST v{__version__} - Use CTRL+C to exit')
    MAIN_LOGGER.debug(f'starting ESST {__version__}')

    from esst import discord_bot
    bot = discord_bot.DiscordBot(ctx)

    from esst import dcs
    app = dcs.App(ctx)
    socket = dcs.DCSListener(ctx)

    ctx.loop.create_task(bot.run())
    ctx.loop.create_task(app.run())
    ctx.loop.create_task(socket.run())
    ctx.loop.create_task(watch_for_exceptions(ctx))

    try:
        ctx.loop.run_forever()

    except KeyboardInterrupt:

        MAIN_LOGGER.info('ESST has been interrupted by user request, closing all threads')

        ctx.exit = True

        ctx.loop.run_until_complete(app.exit())
        ctx.loop.run_until_complete(socket.exit())
        ctx.loop.run_until_complete(bot.exit())

        ctx.loop.run_until_complete(asyncio.gather(*asyncio.Task.all_tasks()))

    finally:
        ctx.loop.close()


if __name__ == '__main__':
    main()  # pylint: disable=no-value-for-parameter
