# coding=utf-8
"""
Main entry point
"""
import asyncio
import logging
import queue
import sys

import click


async def watch_for_exceptions():
    """
    Dummy loop to wake up asyncio event loop from time to time
    """
    from esst.core import CTX
    while True:
        if CTX.exit:
            break
        await asyncio.sleep(0.1)


def _check_wan_and_start_wan_monitor(loop, logger, context):
    import esst.wan
    context.wan = loop.run_until_complete(esst.wan.wan_available())
    if not context.wan:
        logger.error('there is no internet connection available')
        sys.exit(1)
    loop.create_task(esst.wan.monitor_connection())


def _set_console_title(esst_version):
    import ctypes
    ctypes.windll.kernel32.SetConsoleTitleW('ESST v%s - Use CTRL+C to exit', esst_version)


def _init_atis_module():
    import esst.atis.init
    esst.atis.init.init_atis_module()


def _setup_logging_debug(version, logger, console_handler, debug, config_debug):
    logger.debug('Starting ESST version %s', version)
    if debug:
        console_handler.setLevel(logging.DEBUG)
        logger.warning('debug output is active: command line')
    elif config_debug:
        console_handler.setLevel(logging.DEBUG)
        logger.warning('debug output is active: config file')


def sigint_handler(*_):
    """
    Catches exit signal (triggered byu CTRL+C)

    Args:
        *_: frame

    """
    from esst import LOGGER, core
    LOGGER.info('ESST has been interrupted by user request, shutting down')
    core.CTX.exit = True


# TODO: add command to get airports ICAO from name
@click.group(invoke_without_command=True)  # noqa: C901
@click.option('--debug', '-d', help='More console output', is_flag=True)
def main(debug: bool):  # pylint: disable=too-many-locals
    """
    Main entry point

    Args:
        debug: show more verbose console output
    """
    from esst import __version__, LOGGER, LOGGING_CONSOLE_HANDLER, config
    config.init()

    from esst.core import CTX
    from esst import ESSTConfig, DiscordBotConfig, DCSConfig, ListenerConfig, ServerConfig

    from esst.sentry.sentry import SENTRY
    SENTRY.register_context('App context', CTX)
    CTX.sentry = SENTRY

    _setup_logging_debug(__version__, LOGGER, LOGGING_CONSOLE_HANDLER, debug, ESSTConfig.DEBUG())

    LOGGER.debug('instantiating main event loop')
    loop = asyncio.get_event_loop()
    CTX.loop = loop

    _check_wan_and_start_wan_monitor(loop, LOGGER, CTX)

    CTX.start_discord_loop = DiscordBotConfig.DISCORD_START_BOT()
    CTX.start_server_loop = ServerConfig.SERVER_START_LOOP()
    CTX.start_dcs_loop = DCSConfig.DCS_START_LOOP()
    CTX.start_listener_loop = ListenerConfig.LISTENER_START_LOOP()

    if not DCSConfig.DCS_CAN_START():
        CTX.dcs_blocker.append('config')

    CTX.dcs_setup_dedi_config = DCSConfig.DCS_INSTALL_DEDICATED_CONFIG()
    CTX.dcs_install_hooks = DCSConfig.DCS_INSTALL_HOOKS()
    CTX.dcs_auto_mission = DCSConfig.DCS_AUTO_MISSION_ENABLE()

    loop = asyncio.get_event_loop()
    # loop.set_debug(True)
    CTX.discord_msg_queue = queue.Queue()

    _set_console_title(__version__)

    from esst import FS
    FS.init()

    from esst.utils import clean_all_folder, assign_ports
    clean_all_folder()
    assign_ports()

    _init_atis_module()

    import esst.discord_bot.discord_bot
    discord_loop = esst.discord_bot.discord_bot.App()

    from esst.dcs import dcs
    dcs_loop = dcs.App()

    from esst.server import server
    server_loop = server.App()

    from esst.listener.listener import DCSListener
    listener_loop = DCSListener()

    futures = asyncio.gather(
        loop.create_task(discord_loop.run()),
        loop.create_task(dcs_loop.run()),
        loop.create_task(listener_loop.run()),
        loop.create_task(server_loop.run()),
        loop.create_task(watch_for_exceptions()),
    )

    import signal
    signal.signal(signal.SIGINT, sigint_handler)
    loop.run_until_complete(futures)
    LOGGER.debug('main loop is done, killing DCS')

    futures = asyncio.gather(  # type: ignore
        loop.create_task(dcs_loop.kill_running_app()),
        loop.create_task(listener_loop.run_until_dcs_is_closed()),
    )

    loop.run_until_complete(futures)

    LOGGER.debug('all done !')


if __name__ == '__main__':
    main()  # pylint: disable=no-value-for-parameter
