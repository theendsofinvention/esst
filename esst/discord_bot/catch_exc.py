# coding=utf-8
"""
Catches connection error in Discord bot
"""

import asyncio
import logging

import aiohttp
import websockets.exceptions
from discord import HTTPException

from esst.core import CTX

LOGGER = logging.getLogger('discord')
LOGGER.setLevel(logging.DEBUG)
_FH = logging.FileHandler('discord.log', mode='w', encoding='utf8')
LOGGER.addHandler(_FH)


def _pass_exception(exc: Exception):
    LOGGER.error(exc)


def catch_exc(func):
    """
    Decorator to protect discord.client methods
    """

    async def _wrapper(*args, **kwargs):

        try:
            return await func(*args, **kwargs)
        except (websockets.exceptions.InvalidHandshake,
                websockets.exceptions.InvalidState,
                websockets.exceptions.PayloadTooBig,
                websockets.exceptions.WebSocketProtocolError,
                websockets.exceptions.InvalidURI,
                HTTPException) as exc:
            _pass_exception(exc)
        except (aiohttp.ClientError,
                ConnectionError,
                OSError,
                aiohttp.ClientOSError,
                aiohttp.ClientResponseError) as exc:
            await asyncio.sleep(10)
            while not CTX.wan:
                await asyncio.sleep(2)
            _pass_exception(exc)

    return _wrapper
