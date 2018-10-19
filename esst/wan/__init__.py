# coding=utf-8
"""
Monitors WAN connection
"""
import asyncio

import requests
import requests.exceptions

from esst import LOGGER, commands, core


async def wan_available(retry: int = 0):
    """

    Returns: True if connected to WAN

    """
    try:
        response = requests.get('http://google.com', timeout=2)
        commands.DCS.unblock_start('no WAN connection available')
        commands.DISCORD.can_start()
        return bool(response.ok)
    except requests.exceptions.RequestException:
        if retry < 5:
            LOGGER.debug('Internet connection loss detected, retry %s', retry)
            await asyncio.sleep(2)
            result = await wan_available(retry + 1)
            return result
        LOGGER.debug(f'Internet connection loss detected, no more retry')
        commands.DISCORD.cannot_start()
        commands.DCS.block_start('no WAN connection available')
        return False


async def monitor_connection():
    """
    Loop that checks WAN every 5 seconds
    """
    LOGGER.debug('starting connection monitoring loop')

    while not core.CTX.exit:

        current_status = await wan_available()

        if current_status != core.CTX.wan:
            if current_status:
                LOGGER.debug('connected to the Internet')
                commands.DISCORD.say(
                    'I just lost internet connection, server is scheduled to be restarted')
            else:
                LOGGER.warning('internet connection lost !')
                commands.DCS.kill(force=False, queue=True)
            core.CTX.wan = current_status

        await asyncio.sleep(10)

    LOGGER.debug('end of connection monitoring loop')
