# coding=utf-8
import asyncio
import requests
import requests.exceptions

from esst.core import CTX, MAIN_LOGGER
from esst.commands import DCS, DISCORD


LOGGER = MAIN_LOGGER.getChild(__name__)


def wan_available():
    try:
        response = requests.get('http://google.com', timeout=1)
        DCS.can_start()
        DISCORD.can_start()
        return bool(response.ok)
    except requests.exceptions.RequestException:
        DCS.cannot_start()
        DISCORD.cannot_start()
        return False


async def monitor_connection():

    LOGGER.debug('starting connection monitoring loop')

    while not CTX.exit:

        current_status = wan_available()

        if current_status != CTX.wan:
            if current_status:
                LOGGER.debug('connected to the Internet')
                DISCORD.say('I just lost internet connection, server is scheduled to be restarted')
            else:
                LOGGER.warning('internet connection lost !')
                DCS.kill(force=False, queue=True)
            CTX.wan = current_status

        await asyncio.sleep(2)

    LOGGER.debug('end of connection monitoring loop')



if __name__ == '__main__':
    print(wan_available())

