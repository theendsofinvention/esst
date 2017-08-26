# coding=utf-8

import asyncio
from esst.core import ServerStatus
from esst.core import CFG, MAIN_LOGGER, CTX


LOGGER = MAIN_LOGGER.getChild(__name__)


class App:

    def __init__(self):
        pass

    async def run(self):
        """
        Entry point of the loop
        """
        if not CTX.dcs_start:
            LOGGER.debug('skipping DCS application loop')
            return
        while True:
            if CTX.exit:
                break
            await asyncio.sleep(0.1)

        LOGGER.debug('end of Server computer loop')

    async def exit(self):
        pass
