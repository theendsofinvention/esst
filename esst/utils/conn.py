# coding=utf-8
"""
Checks WAN connection
"""
import asyncio

import ipgetter
import requests
import requests.exceptions

from esst.commands import DCS, DISCORD
from esst.core import CTX, MAIN_LOGGER

LOGGER = MAIN_LOGGER.getChild(__name__)


def external_ip():
    """
    Returns: external IP of this machine
    """
    return ipgetter.IPgetter().get_externalip()


async def wan_available(retry: int = 0):
    """

    Returns: True if connected to WAN

    """
    try:
        response = requests.get('http://google.com', timeout=2)
        # DCS.can_start()
        DISCORD.can_start()
        return bool(response.ok)
    except requests.exceptions.RequestException:
        if retry < 5:
            LOGGER.debug(f'Internet connection loss detected, retry {retry}')
            await asyncio.sleep(2)
            result = await wan_available(retry + 1)
            return result
        LOGGER.debug(f'Internet connection loss detected, no more retry')
        # DCS.cannot_start()
        DISCORD.cannot_start()
        return False


async def monitor_connection():

    """
    Loop that checks WAN every 5 seconds
    """
    LOGGER.debug('starting connection monitoring loop')

    while not CTX.exit:

        current_status = await wan_available()

        if current_status != CTX.wan:
            if current_status:
                LOGGER.debug('connected to the Internet')
                DISCORD.say(
                    'I just lost internet connection, server is scheduled to be restarted')
            else:
                LOGGER.warning('internet connection lost !')
                DCS.kill(force=False, queue=True)
            CTX.wan = current_status

        await asyncio.sleep(10)

    LOGGER.debug('end of connection monitoring loop')
